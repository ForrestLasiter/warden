"""System sweep: scan the high-value places malware likes to hide.

Instead of asking the user to point at a folder, a sweep automatically gathers
the spots that matter for persistence and execution, then scans them:

  * Autoruns      - registry Run/RunOnce keys (HKCU + HKLM) and Startup folders
  * Processes     - the on-disk image of every running process
  * Scheduled     - executables referenced by Scheduled Tasks (Windows)
  * Persistence   - Linux: systemd units, cron, XDG autostart, shell start-up
                    files, init scripts, ld.so.preload. macOS: LaunchAgents /
                    LaunchDaemons, login items, cron, periodic scripts.
                    (see warden.persistence)
  * Temp          - %TEMP% and the Windows temp dir
  * Downloads     - the user's Downloads folder

On top of the normal engine findings, the sweep adds a *location* heuristic:
an unsigned executable running from a world-writable / user-profile temp
location (Temp, Downloads, AppData, ProgramData) is suspicious on its own.

Everything is best-effort and degrades gracefully: unreadable keys, access-
denied processes, and non-Windows platforms are skipped, never fatal.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

from . import persistence as _persistence
from . import signature as _signature
from .config import Config
from .models import FileResult, Finding, ScanReport, Severity
from .scanner import ScanLimits, Scanner

IS_WINDOWS = os.name == "nt"

# Directories that are user-writable and a common staging ground for malware.
# An unsigned executable here is worth a second look.
_SUSPICIOUS_DIR_MARKERS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\",
    "\\programdata\\", "\\public\\", "/tmp/", "/downloads/",
)

_EXE_EXTS = {".exe", ".dll", ".scr", ".com", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js"}


@dataclass(slots=True)
class SweepCategory:
    name: str
    description: str
    paths: list[Path] = field(default_factory=list)


class SystemSweep:
    def __init__(self, config: Config | None = None, scanner: Scanner | None = None):
        self.config = config or Config.load()
        self.scanner = scanner or Scanner(self.config)
        self._persistence_scan: _persistence.PersistenceScan | None = None

    # -- collection -------------------------------------------------------
    def collect(self, *, quick: bool = False) -> list[SweepCategory]:
        cats: list[SweepCategory] = []
        cats.append(self._autoruns())
        cats.append(self._processes())
        if IS_WINDOWS:
            cats.append(self._scheduled_tasks())
        else:
            cats.append(self._persistence(quick=quick))
        cats.append(self._temp(quick=quick))
        cats.append(self._downloads(quick=quick))
        # Drop empties for a tidy report.
        return [c for c in cats if c.paths]

    def _autoruns(self) -> SweepCategory:
        cat = SweepCategory("autoruns", "Startup entries (registry Run keys + Startup folders)")
        seen: set[str] = set()

        def add(p: Path):
            try:
                rp = p.resolve()
            except OSError:
                rp = p
            key = str(rp).lower()
            if key not in seen and rp.is_file():
                seen.add(key)
                cat.paths.append(rp)

        # Startup folders (cross-platform-ish: Windows Start Menu Startup)
        candidates: list[Path] = []
        if IS_WINDOWS:
            appdata = os.environ.get("APPDATA", "")
            programdata = os.environ.get("PROGRAMDATA", "")
            if appdata:
                candidates.append(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
            if programdata:
                candidates.append(Path(programdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
        else:
            candidates.append(Path.home() / ".config/autostart")
        for folder in candidates:
            if folder.is_dir():
                for entry in folder.iterdir():
                    if entry.is_file():
                        add(entry)

        # Registry Run keys (Windows only)
        if IS_WINDOWS:
            for exe in _registry_autorun_executables():
                add(exe)
        return cat

    def _processes(self) -> SweepCategory:
        cat = SweepCategory("processes", "On-disk image of running processes")
        if psutil is None:
            return cat
        seen: set[str] = set()
        for proc in psutil.process_iter(["exe"]):
            try:
                exe = proc.info.get("exe")
            except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                continue
            if not exe:
                continue
            key = exe.lower()
            if key in seen:
                continue
            seen.add(key)
            p = Path(exe)
            if p.is_file():
                cat.paths.append(p)
        return cat

    def _scheduled_tasks(self) -> SweepCategory:
        cat = SweepCategory("scheduled", "Executables referenced by Scheduled Tasks")
        exes = _scheduled_task_executables()
        seen: set[str] = set()
        for exe in exes:
            key = str(exe).lower()
            if key not in seen and exe.is_file():
                seen.add(key)
                cat.paths.append(exe)
        return cat

    def _persistence(self, *, quick: bool) -> SweepCategory:
        cat = SweepCategory(
            "persistence",
            "Start-up persistence (systemd, cron, launchd, login items, shell profiles)")
        self._persistence_scan = _persistence.collect(full=not quick)
        cat.paths = [p for p in self._persistence_scan.files() if p.is_file()]
        return cat

    def _temp(self, *, quick: bool) -> SweepCategory:
        cat = SweepCategory("temp", "Temp directories")
        dirs = []
        t = os.environ.get("TEMP") or os.environ.get("TMP")
        if t:
            dirs.append(Path(t))
        if IS_WINDOWS:
            windir = os.environ.get("WINDIR", "C:/Windows")
            dirs.append(Path(windir) / "Temp")
        else:
            dirs.append(Path("/tmp"))
        cat.paths = _collect_files(dirs, quick=quick, exe_only=quick)
        return cat

    def _downloads(self, *, quick: bool) -> SweepCategory:
        cat = SweepCategory("downloads", "Downloads folder")
        dl = Path.home() / "Downloads"
        cat.paths = _collect_files([dl], quick=quick, exe_only=False)
        return cat

    # -- running ----------------------------------------------------------
    def run(
        self,
        *,
        quick: bool = False,
        progress: Callable[[FileResult], None] | None = None,
        limits: ScanLimits | None = None,
    ) -> tuple[ScanReport, list[SweepCategory]]:
        categories = self.collect(quick=quick)
        # Flatten unique paths, remembering category membership for the report.
        all_paths: list[Path] = []
        cat_of: dict[str, str] = {}
        for cat in categories:
            for p in cat.paths:
                key = str(p).lower()
                if key not in cat_of:
                    cat_of[key] = cat.name
                    all_paths.append(p)

        report = self.scanner.scan_files(all_paths, progress=progress, limits=limits)
        report.root = "<system-sweep>"

        # Location heuristic + tag each result with its sweep category.
        for result in report.results:
            result_key = str(Path(result.path)).lower()
            category = cat_of.get(result_key, "other")
            # stash category in the worst finding's meta, or as a note
            self._augment_location(result, category)
        self._apply_persistence(report)
        return report, categories

    def _apply_persistence(self, report: ScanReport) -> None:
        """Judge each persistence registration on what it launches, and attach
        the verdict to the file that defines it."""
        scan = self._persistence_scan
        if scan is None:
            return
        # Locations we could not read (often root-only) are a coverage gap.
        report.unreadable.extend(scan.unreadable)
        by_path = {str(Path(r.path)): r for r in report.results}
        texts: dict[str, str | None] = {}
        for item in scan.items:
            src = item.source_path
            if src is None:
                # No file behind it (the user crontab): scan the text in memory.
                result = by_path.get(item.source)
                if result is None:
                    result = self.scanner.scan_bytes(item.source, item.text.encode("utf-8", "replace"))
                    by_path[item.source] = result
                    report.results.append(result)
                    report.files_scanned += 1
                text: str | None = item.text
            else:
                result = by_path.get(str(src))
                if result is None:
                    continue
                if str(src) not in texts:
                    texts[str(src)] = _read_text(src)
                text = texts[str(src)]
            known = {(f.name, f.meta.get("command"), f.meta.get("path")) for f in result.findings}
            for finding in _persistence.assess(item, text):
                key = (finding.name, finding.meta.get("command"), finding.meta.get("path"))
                if key not in known:
                    known.add(key)
                    result.findings.append(finding)

    def _augment_location(self, result: FileResult, category: str) -> None:
        path = Path(result.path)
        path_lower = str(path).lower()
        in_suspicious = any(m in path_lower for m in _SUSPICIOUS_DIR_MARKERS)
        if path.suffix.lower() in _EXE_EXTS and in_suspicious:
            signed = _is_signed(path)
            if signed is False:
                result.findings.append(Finding(
                    engine="sweep",
                    name="unsigned-exe-in-writable-location",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Unsigned executable in a user-writable location "
                        f"({category}); common malware staging pattern"
                    ),
                    meta={"category": category, "signed": False},
                ))
                result.meta.setdefault("signature", _signature.signature_info(path))


# -- helpers -------------------------------------------------------------
def _read_text(path: Path, limit: int = 256 * 1024) -> str | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return None


def _collect_files(dirs: list[Path], *, quick: bool, exe_only: bool) -> list[Path]:
    out: list[Path] = []
    max_files = 500 if quick else 5000
    for d in dirs:
        if not d.is_dir():
            continue
        try:
            walker = os.walk(d)
        except OSError:
            continue
        for root, _sub, files in walker:
            for name in files:
                p = Path(root) / name
                if exe_only and p.suffix.lower() not in _EXE_EXTS:
                    continue
                out.append(p)
                if len(out) >= max_files:
                    return out
            if quick:
                # In quick mode don't descend deeply; only the top level.
                break
    return out


def _registry_autorun_executables() -> list[Path]:
    """Read Run/RunOnce values and extract the referenced executable paths."""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []

    exes: list[Path] = []
    hives = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, subkey in hives:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        _name, value, _type = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    exes.extend(_extract_exe_paths(str(value)))
        except OSError:
            continue
    return exes


def _scheduled_task_executables() -> list[Path]:
    """Parse `schtasks /query /v /fo csv` and pull the 'Task To Run' column."""
    if not IS_WINDOWS:
        return []
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/v", "/fo", "csv"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 or not proc.stdout:
        return []

    import csv
    import io
    exes: list[Path] = []
    reader = csv.DictReader(io.StringIO(proc.stdout))
    for row in reader:
        run = row.get("Task To Run") or row.get("Task To Run ") or ""
        exes.extend(_extract_exe_paths(run))
    return exes


def _extract_exe_path(command: str) -> Path | None:
    """Best-effort: pull a real file path out of a command line string."""
    command = command.strip()
    if not command:
        return None
    # Quoted path first: "C:\Program Files\app.exe" -args
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 0:
            candidate = command[1:end]
            p = Path(os.path.expandvars(candidate))
            return p if p.is_file() else None
    # Otherwise take up to the first .exe/.dll/.bat/etc. token.
    expanded = os.path.expandvars(command)
    tokens = expanded.split()
    # Rebuild progressively to handle unquoted spaces in paths.
    acc = ""
    for tok in tokens:
        acc = (acc + " " + tok).strip() if acc else tok
        low = acc.lower()
        for ext in _EXE_EXTS:
            if low.endswith(ext):
                p = Path(acc)
                if p.is_file():
                    return p
    first = Path(tokens[0]) if tokens else None
    return first if first and first.is_file() else None


# Interpreters/LOLBins that host a payload passed as an argument. When the
# primary executable is one of these, the real threat is the script/DLL it runs.
_INTERPRETERS = {
    "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "msbuild.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe",
}


def _split_command(command: str) -> list[str]:
    """Split a command line on whitespace, respecting double-quoted spans."""
    toks: list[str] = []
    cur: list[str] = []
    quoted = False
    for ch in command:
        if ch == '"':
            quoted = not quoted
        elif ch.isspace() and not quoted:
            if cur:
                toks.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        toks.append("".join(cur))
    return toks


def _extract_exe_paths(command: str) -> list[Path]:
    """All plausible on-disk file paths referenced by a command line.

    Returns the primary executable AND, when that is an interpreter/LOLBin (or
    the primary can't be resolved), any file-path arguments too - so script- and
    DLL-based persistence (``wscript evil.vbs``, ``rundll32 evil.dll,Run``) is
    actually scanned instead of just the signed interpreter.
    """
    out: list[Path] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        cand = os.path.expandvars(raw.strip().strip('"'))
        if not cand:
            return
        # rundll32-style "evil.dll,Entry"
        if "," in cand:
            try:
                if not Path(cand).is_file():
                    cand = cand.split(",", 1)[0]
            except OSError:
                cand = cand.split(",", 1)[0]
        p = Path(cand)
        try:
            is_file = p.is_file()
        except OSError:
            is_file = False
        if is_file:
            key = str(p).lower()
            if key not in seen:
                seen.add(key)
                out.append(p)

    primary = _extract_exe_path(command)
    if primary:
        add(str(primary))
    is_interpreter = (primary is not None and primary.name.lower() in _INTERPRETERS)
    if is_interpreter or primary is None:
        for tok in _split_command(command):
            add(tok)
    return out


_SIGN_CACHE: dict[str, bool | None] = {}


def _powershell_exe() -> str:
    """Absolute path to the system PowerShell (see warden.signature)."""
    return _signature.powershell_exe()


def _is_signed(path: Path) -> bool | None:
    """Return True/False if we can determine Authenticode status, else None.

    Windows only. Uses PowerShell Get-AuthenticodeSignature. Result cached.
    """
    if not IS_WINDOWS:
        return None
    key = str(path)
    if key in _SIGN_CACHE:
        return _SIGN_CACHE[key]
    # The path is passed to PowerShell out-of-band (environment variable), never
    # interpolated into the script: see warden.signature.authenticode_info.
    status = _signature.authenticode_info(path).get("status")
    result: bool | None
    if status == "valid":
        result = True
    elif status in ("unsigned", "invalid", "untrusted"):
        result = False
    else:
        result = None
    _SIGN_CACHE[key] = result
    return result
