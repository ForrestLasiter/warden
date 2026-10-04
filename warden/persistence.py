"""Persistence discovery for Linux and macOS.

"Persistence" is how malware survives a reboot: it registers itself with one of
the operating system's start-something-automatically mechanisms. A system sweep
needs to look at exactly those registrations - both the definition file (a
systemd unit, a crontab, a launchd plist) and the program it launches.

Linux
  * systemd units          /etc/systemd/system, /etc/systemd/user,
                           /usr/local/lib/systemd/system, ~/.config/systemd/user
                           (+ the distro's /usr/lib and /lib trees on a full sweep)
  * cron                   /etc/crontab, /etc/cron.d, /etc/cron.{hourly,daily,weekly,
                           monthly}, /var/spool/cron, /etc/anacrontab, the user crontab
  * XDG autostart          ~/.config/autostart, /etc/xdg/autostart
  * shell start-up files   ~/.bashrc, ~/.profile, ~/.zshrc, /etc/profile.d, ...
  * SysV / rc              /etc/rc.local, /etc/init.d
  * dynamic linker         /etc/ld.so.preload

macOS
  * launchd                ~/Library/LaunchAgents, /Library/LaunchAgents,
                           /Library/LaunchDaemons
  * login items            the background-task-management store (best effort) and the
                           legacy com.apple.loginitems.plist
  * cron / periodic        user crontab, /etc/crontab, /etc/periodic/*
  * shell start-up files   ~/.zshrc, ~/.zprofile, ~/.bash_profile, /etc/zshrc, ...
  * legacy                 /Library/StartupItems

Every reader is best-effort: unreadable or root-only locations are skipped and
counted, never fatal. ``root`` and ``home`` are injectable so the parsers can be
tested against a fake filesystem on any platform.

Not covered (documented limits): udev rules, at(1) jobs, kernel modules, PAM
modules, SSH ``authorized_keys`` commands, browser extensions, and macOS
configuration profiles / system extensions.
"""

from __future__ import annotations

import os
import plistlib
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, Severity

_MAX_CONFIG_BYTES = 256 * 1024     # a persistence definition is a small text file
_MAX_ITEMS = 5000
_MAX_DIR_ENTRIES = 2000

_SYSTEMD_EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop",
                      "ExecStopPost", "ExecReload", "ExecCondition")
_SHELL_RC_USER = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc",
                  ".zprofile", ".zshenv", ".zlogin", ".config/fish/config.fish")
_SHELL_RC_SYSTEM = ("etc/profile", "etc/bash.bashrc", "etc/bashrc", "etc/zshrc",
                    "etc/zprofile", "etc/zshenv", "etc/zsh/zshrc", "etc/zsh/zprofile",
                    "etc/zsh/zshenv", "etc/environment")

# Directories anyone can write to: nothing legitimate should persist from here.
_STAGING_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/",
                 "/Users/Shared/", "/run/shm/")

# (pattern, reason, severity) - matched against a persistence command line.
_SUSPICIOUS = [
    (re.compile(r"\b(curl|wget|fetch)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b", re.I),
     "downloads a script and pipes it straight into a shell", Severity.HIGH),
    (re.compile(r"\b(curl|wget)\b[^|;&\n]*\|\s*(python[0-9.]*|perl|ruby|node)\b", re.I),
     "downloads code and pipes it into an interpreter", Severity.HIGH),
    (re.compile(r"base64\s+(-d|-D|--decode)\b[^|\n]*\|\s*(ba|z|k|da)?sh\b", re.I),
     "decodes a base64 blob and executes it", Severity.HIGH),
    (re.compile(r"/dev/(tcp|udp)/[\w.\-]+/\d+"),
     "opens a raw network socket from the shell (reverse-shell pattern)", Severity.HIGH),
    (re.compile(r"\b(nc|ncat|netcat)\b[^\n]*\s-(e|c)\s", re.I),
     "starts netcat with a program attached (reverse-shell pattern)", Severity.HIGH),
    (re.compile(r"\bbash\s+-i\b[^\n]*>&|\bsocat\b[^\n]*\bexec:", re.I),
     "starts an interactive shell wired to a socket (reverse-shell pattern)", Severity.HIGH),
    (re.compile(r"\b(python[0-9.]*|perl|ruby|php)\s+-[ce]\s+[^\n]*(socket|base64|exec\(|eval\()", re.I),
     "runs an inline interpreter one-liner that uses sockets or decoding", Severity.MEDIUM),
    (re.compile(r"\bLD_PRELOAD=|\bDYLD_INSERT_LIBRARIES=", re.I),
     "injects a library into the launched process", Severity.MEDIUM),
    (re.compile(r"\bosascript\b[^\n]*do shell script", re.I),
     "runs a shell command through AppleScript", Severity.MEDIUM),
]


@dataclass(slots=True)
class PersistenceItem:
    kind: str                     # systemd | cron | autostart | shell-rc | init | ld-preload | launchd | login-item
    source: str                   # where it's defined (a path, or "<user crontab>")
    command: str = ""             # the command line it launches, if any
    label: str = ""
    targets: list[Path] = field(default_factory=list)   # files it references that exist
    text: str = ""                # definition text when there is no source file on disk

    @property
    def source_path(self) -> Path | None:
        return None if self.source.startswith("<") else Path(self.source)


@dataclass(slots=True)
class PersistenceScan:
    items: list[PersistenceItem] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)   # locations we could not read

    def files(self) -> list[Path]:
        """Unique on-disk files worth scanning: definitions and their targets."""
        seen: set[str] = set()
        out: list[Path] = []
        for item in self.items:
            for p in ([item.source_path] if item.source_path else []) + item.targets:
                key = str(p)
                if key not in seen:
                    seen.add(key)
                    out.append(p)
        return out


class _Walker:
    """Filesystem access relative to an injectable root/home (for tests)."""

    def __init__(self, root: Path, home: Path, scan: PersistenceScan):
        self.root, self.home, self.scan = root, home, scan

    def at(self, absolute: str) -> Path:
        """Map an absolute path string ('/etc/crontab') under the root."""
        return self.root / absolute.lstrip("/")

    def read(self, path: Path) -> str | None:
        try:
            with open(path, "rb") as fh:
                return fh.read(_MAX_CONFIG_BYTES).decode("utf-8", errors="replace")
        except FileNotFoundError:
            return None
        except OSError as exc:
            self.scan.unreadable.append(f"{path} ({exc.strerror or exc})")
            return None

    def listdir(self, path: Path, pattern: str = "*") -> list[Path]:
        try:
            if not path.is_dir():
                return []
            return sorted(p for p in path.glob(pattern))[:_MAX_DIR_ENTRIES]
        except OSError as exc:
            self.scan.unreadable.append(f"{path} ({exc.strerror or exc})")
            return []

    def resolve_targets(self, command: str) -> list[Path]:
        """Existing files referenced by a command line (program + path arguments)."""
        out: list[Path] = []
        seen: set[str] = set()
        for tok in _tokens(command):
            tok = tok.split("=", 1)[1] if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=/", tok) else tok
            if tok.startswith("~/"):
                cand = self.home / tok[2:]
            elif tok.startswith("$HOME/"):
                cand = self.home / tok[6:]
            elif tok.startswith("/"):
                cand = self.at(tok)
            else:
                continue
            try:
                ok = cand.is_file()
            except OSError:
                ok = False
            if ok and str(cand) not in seen:
                seen.add(str(cand))
                out.append(cand)
        return out[:16]

    def add(self, kind: str, source: Path | str, command: str = "", label: str = "",
            text: str = "") -> None:
        if len(self.scan.items) >= _MAX_ITEMS:
            return
        self.scan.items.append(PersistenceItem(
            kind=kind, source=str(source), command=command.strip()[:2000], label=label[:200],
            targets=self.resolve_targets(command) if command else [], text=text))


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, comments=False, posix=True)
    except ValueError:        # unbalanced quotes - fall back to a plain split
        return command.split()


# -- parsers (pure: text in, commands out) -------------------------------
def parse_systemd_unit(text: str) -> list[str]:
    """Command lines from a unit file's Exec* directives."""
    out: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = (pending + raw).strip()
        pending = ""
        if line.endswith("\\"):           # continuation
            pending = line[:-1] + " "
            continue
        if not line or line[0] in "#;[":
            continue
        key, sep, value = line.partition("=")
        if not sep or key.strip() not in _SYSTEMD_EXEC_KEYS:
            continue
        # Strip systemd's special executable prefixes: @ - : + !
        value = value.strip().lstrip("@-:+!").strip()
        if value:
            out.append(value)
    return out


_CRON_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_CRON_SHORTCUTS = ("@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily",
                   "@midnight", "@hourly")


def parse_crontab(text: str, *, system: bool) -> list[str]:
    """Commands from crontab text. ``system`` crontabs (/etc/crontab, cron.d)
    carry an extra user field before the command."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or _CRON_ENV_RE.match(line):
            continue
        parts = line.split(None, 1)
        if parts[0].lower() in _CRON_SHORTCUTS:
            rest = parts[1] if len(parts) > 1 else ""
        else:
            fields = line.split(None, 5)
            if len(fields) < 6:
                continue
            rest = fields[5]
        if system:
            bits = rest.split(None, 1)
            rest = bits[1] if len(bits) > 1 else ""
        if rest.strip():
            out.append(rest.strip())
    return out


def parse_desktop_entry(text: str) -> list[str]:
    """Exec= command lines of an XDG .desktop file (field codes removed)."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("Exec=", "TryExec=")):
            cmd = re.sub(r"%[a-zA-Z]", "", line.split("=", 1)[1]).strip()
            if cmd:
                out.append(cmd)
    return out


def parse_launchd_plist(data: bytes) -> tuple[str, str, dict]:
    """(label, command, extra) from a launchd property list (XML or binary).

    Raises ValueError if the data isn't a usable plist.
    """
    try:
        pl = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 - plistlib raises several types
        raise ValueError(f"not a property list: {exc}") from None
    if not isinstance(pl, dict):
        raise ValueError("launchd plist root is not a dictionary")
    args = pl.get("ProgramArguments")
    parts: list[str] = []
    if isinstance(pl.get("Program"), str):
        parts.append(pl["Program"])
    if isinstance(args, list):
        strs = [a for a in args if isinstance(a, str)]
        # ProgramArguments[0] is usually the program again; avoid doubling it.
        parts += strs[1:] if parts and strs and strs[0] == parts[0] else strs
    command = " ".join(shlex.quote(p) for p in parts)
    env = pl.get("EnvironmentVariables")
    extra = {
        "run_at_load": bool(pl.get("RunAtLoad")),
        "keep_alive": bool(pl.get("KeepAlive")),
        "dyld_insert": bool(isinstance(env, dict) and env.get("DYLD_INSERT_LIBRARIES")),
    }
    return str(pl.get("Label", "")), command, extra


# -- collectors ----------------------------------------------------------
def linux_persistence(root: Path | None = None, home: Path | None = None, *,
                      full: bool = True, user_crontab: bool = True) -> PersistenceScan:
    scan = PersistenceScan()
    w = _Walker(root or Path("/"), home or Path.home(), scan)

    unit_dirs = [w.at("/etc/systemd/system"), w.at("/etc/systemd/user"),
                 w.at("/usr/local/lib/systemd/system"), w.at("/run/systemd/system"),
                 w.home / ".config/systemd/user"]
    if full:
        unit_dirs += [w.at("/usr/lib/systemd/system"), w.at("/lib/systemd/system"),
                      w.at("/usr/lib/systemd/user")]
    seen_dirs: set[str] = set()
    for d in unit_dirs:
        real = os.path.realpath(d)       # /lib is usually a symlink to /usr/lib
        if real in seen_dirs:
            continue
        seen_dirs.add(real)
        for unit in w.listdir(d, "**/*.service"):
            text = w.read(unit)
            if text is None:
                continue
            cmds = parse_systemd_unit(text)
            for cmd in cmds or [""]:
                w.add("systemd", unit, cmd, label=unit.name)

    _cron(w, user_crontab=user_crontab)

    for d in (w.home / ".config/autostart", w.at("/etc/xdg/autostart")):
        for entry in w.listdir(d, "*.desktop"):
            text = w.read(entry)
            if text is None:
                continue
            for cmd in parse_desktop_entry(text) or [""]:
                w.add("autostart", entry, cmd, label=entry.name)

    _shell_rc(w)

    rc_local = w.at("/etc/rc.local")
    if rc_local.is_file():
        w.add("init", rc_local, label="rc.local")
    for script in w.listdir(w.at("/etc/init.d")):
        if script.is_file():
            w.add("init", script, label=script.name)

    preload = w.at("/etc/ld.so.preload")
    text = w.read(preload)
    if text is not None:
        libs = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        w.add("ld-preload", preload, " ".join(libs), label="ld.so.preload")
    return scan


def macos_persistence(root: Path | None = None, home: Path | None = None, *,
                      full: bool = True, user_crontab: bool = True) -> PersistenceScan:
    scan = PersistenceScan()
    w = _Walker(root or Path("/"), home or Path.home(), scan)

    for d in (w.home / "Library/LaunchAgents", w.at("/Library/LaunchAgents"),
              w.at("/Library/LaunchDaemons")):
        for plist in w.listdir(d, "*.plist"):
            try:
                with open(plist, "rb") as fh:
                    raw = fh.read(_MAX_CONFIG_BYTES)
            except OSError as exc:
                scan.unreadable.append(f"{plist} ({exc.strerror or exc})")
                continue
            try:
                label, command, extra = parse_launchd_plist(raw)
            except ValueError:
                w.add("launchd", plist, label=plist.name)     # still scan the file
                continue
            if extra["dyld_insert"]:
                command = "DYLD_INSERT_LIBRARIES=1 " + command
            w.add("launchd", plist, command, label=label or plist.name)

    # Login items. The modern store is an opaque keyed archive; pull the app
    # paths out of it as text rather than modelling the format.
    btm = w.home / ("Library/Application Support/com.apple.backgroundtaskmanagementagent/"
                    "backgrounditems.btm")
    legacy = w.home / "Library/Preferences/com.apple.loginitems.plist"
    for store in (btm, legacy):
        try:
            with open(store, "rb") as fh:
                blob = fh.read(4 * 1024 * 1024)
        except FileNotFoundError:
            continue
        except OSError as exc:
            scan.unreadable.append(f"{store} ({exc.strerror or exc})")
            continue
        apps = sorted({m.decode("utf-8", "replace") for m in
                       re.findall(rb"(/(?:Applications|Users|Library|opt|private)/[\x20-\x7e]{1,300}?\.app)", blob)})
        w.add("login-item", store, label=store.name)
        for app in apps[:200]:
            item = PersistenceItem(kind="login-item", source=str(store), command=app, label=Path(app).name)
            exe = _app_executable(w.at(app))
            if exe is not None:
                item.targets.append(exe)
            scan.items.append(item)

    _cron(w, user_crontab=user_crontab)
    for period in ("daily", "weekly", "monthly"):
        for script in w.listdir(w.at(f"/etc/periodic/{period}")):
            if script.is_file():
                w.add("cron", script, label=f"periodic/{period}/{script.name}")

    _shell_rc(w)

    for item_dir in w.listdir(w.at("/Library/StartupItems")):
        for f in w.listdir(item_dir):
            if f.is_file():
                w.add("init", f, label=f"StartupItems/{item_dir.name}")
    return scan


def _app_executable(app: Path) -> Path | None:
    """The main executable inside a .app bundle, if we can find it."""
    try:
        with open(app / "Contents/Info.plist", "rb") as fh:
            info = plistlib.loads(fh.read(_MAX_CONFIG_BYTES))
        name = info.get("CFBundleExecutable") if isinstance(info, dict) else None
        if isinstance(name, str) and "/" not in name:
            exe = app / "Contents/MacOS" / name
            if exe.is_file():
                return exe
    except Exception:  # noqa: BLE001 - missing/corrupt bundle
        pass
    return None


def _cron(w: _Walker, *, user_crontab: bool) -> None:
    for path, system in ((w.at("/etc/crontab"), True), (w.at("/etc/anacrontab"), False)):
        text = w.read(path)
        if text is None:
            continue
        cmds = parse_crontab(text, system=system) if system else _anacron_commands(text)
        for cmd in cmds or [""]:
            w.add("cron", path, cmd, label=path.name)
    for f in w.listdir(w.at("/etc/cron.d")):
        text = w.read(f) if f.is_file() else None
        if text is None:
            continue
        for cmd in parse_crontab(text, system=True) or [""]:
            w.add("cron", f, cmd, label=f"cron.d/{f.name}")
    for period in ("hourly", "daily", "weekly", "monthly"):
        for script in w.listdir(w.at(f"/etc/cron.{period}")):
            if script.is_file():
                w.add("cron", script, label=f"cron.{period}/{script.name}")
    for spool in ("/var/spool/cron", "/var/spool/cron/crontabs", "/usr/lib/cron/tabs", "/var/at/tabs"):
        for f in w.listdir(w.at(spool)):
            text = w.read(f) if f.is_file() else None
            if text is None:
                continue
            for cmd in parse_crontab(text, system=False) or [""]:
                w.add("cron", f, cmd, label=f"crontab:{f.name}")
    if user_crontab:
        text = _user_crontab_text()
        if text:
            for cmd in parse_crontab(text, system=False):
                w.add("cron", "<user crontab>", cmd, label="user crontab", text=text)


def _anacron_commands(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or _CRON_ENV_RE.match(line):
            continue
        fields = line.split(None, 3)      # period delay job-id command
        if len(fields) == 4:
            out.append(fields[3])
    return out


def _user_crontab_text() -> str:
    """The invoking user's crontab (``crontab -l``); empty if none/unavailable."""
    if sys.platform == "win32":
        return ""
    binary = next((p for p in ("/usr/bin/crontab", "/bin/crontab") if os.path.isfile(p)), None)
    if binary is None:
        return ""
    try:
        proc = subprocess.run([binary, "-l"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _shell_rc(w: _Walker) -> None:
    for rel in _SHELL_RC_USER:
        p = w.home / rel
        if p.is_file():
            w.add("shell-rc", p, label=rel)
    for rel in _SHELL_RC_SYSTEM:
        p = w.root / rel
        if p.is_file():
            w.add("shell-rc", p, label="/" + rel)
    for p in w.listdir(w.at("/etc/profile.d"), "*.sh"):
        if p.is_file():
            w.add("shell-rc", p, label=f"profile.d/{p.name}")


def collect(*, full: bool = True) -> PersistenceScan:
    """Persistence registrations for the running platform (empty on Windows,
    where the sweep's registry/Startup/Scheduled-Task collectors apply)."""
    if sys.platform == "darwin":
        return macos_persistence(full=full)
    if sys.platform.startswith("linux"):
        return linux_persistence(full=full)
    return PersistenceScan()


# -- assessment ----------------------------------------------------------
def assess(item: PersistenceItem, text: str | None = None) -> list[Finding]:
    """Findings for one persistence registration, judged on what it launches.

    ``text`` is the definition's content for kinds without a single command
    (shell start-up files, init scripts); each line is judged as a command.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    def flag(name: str, severity: Severity, description: str, **meta) -> None:
        if name in seen:
            return
        seen.add(name)
        findings.append(Finding(
            engine="persistence", name=name, severity=severity, description=description,
            meta={"kind": item.kind, "label": item.label, **meta}))

    lines = [item.command] if item.command else []
    if text and item.kind in ("shell-rc", "init", "cron"):
        lines += [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")][:2000]

    for line in lines:
        for pattern, reason, severity in _SUSPICIOUS:
            if pattern.search(line):
                flag("suspicious-persistence-command", severity,
                     f"{_kind_name(item.kind)} '{item.label}' {reason}", command=line.strip()[:300])
                break

    if item.kind == "ld-preload" and item.command:
        flag("ld-preload-configured", Severity.MEDIUM,
             "/etc/ld.so.preload forces a library into every process - rarely legitimate, "
             "a classic userland-rootkit technique", libraries=item.command[:300])

    if item.command and item.kind not in ("shell-rc", "login-item"):
        for tok in _tokens(item.command)[:32]:
            path = tok.split("=", 1)[1] if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=/", tok) else tok
            if not path.startswith("/"):
                continue
            if any(path.startswith(d) for d in _STAGING_DIRS):
                flag("persistence-from-writable-location", Severity.MEDIUM,
                     f"{_kind_name(item.kind)} '{item.label}' launches a file from a world-writable "
                     f"directory ({path})", path=path[:300])
            elif Path(path).name.startswith(".") and len(Path(path).name) > 1:
                flag("persistence-hidden-executable", Severity.MEDIUM,
                     f"{_kind_name(item.kind)} '{item.label}' launches a hidden file ({path})",
                     path=path[:300])
    return findings


def _kind_name(kind: str) -> str:
    return {
        "systemd": "systemd unit", "cron": "cron job", "autostart": "autostart entry",
        "shell-rc": "shell start-up file", "init": "init script",
        "ld-preload": "linker preload", "launchd": "launchd job", "login-item": "login item",
    }.get(kind, kind)
