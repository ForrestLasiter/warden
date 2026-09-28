"""Scheduled scans via the OS scheduler.

Warden doesn't run a background daemon. Instead it registers a task with the
native scheduler so scans run even when Warden isn't open:

  * Windows -> Task Scheduler (``schtasks``), tasks live under the \\Warden\\ folder
  * Linux/macOS -> the user crontab, in a block between # WARDEN markers

We also keep our own registry at ``~/.warden/schedules.json`` so ``schedule
list`` is consistent across platforms and remembers the original options.

Scheduled runs invoke ``warden scan/sweep ... --save`` (writes to history) and
never auto-quarantine - isolating files with no human present is too risky, so
findings are recorded for review via ``warden history``.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path

from .config import Config
from .models import Severity
from .storage import file_lock

IS_WINDOWS = os.name == "nt"
_FREQUENCIES = ("hourly", "daily", "weekly")
_CRON_BEGIN = "# >>> WARDEN schedules >>>"
_CRON_END = "# <<< WARDEN schedules <<<"

# A schedule name becomes part of a Task Scheduler task path and a crontab
# comment. Restrict it hard so it cannot traverse the task namespace
# (\Warden\..\Startup\evil) or inject extra crontab lines via a newline.
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# Characters that must never appear in a target path we hand to schtasks/cron.
_BAD_TARGET_CHARS = ("\n", "\r", "\x00", '"')


def _validate_name(name: str) -> None:
    if not _NAME_RE.match(name or ""):
        raise SchedulerError(
            "schedule name must be 1-64 characters of letters, digits, '-' or '_'"
        )


def _validate_target(target: str) -> None:
    if any(c in target for c in _BAD_TARGET_CHARS):
        raise SchedulerError("target path contains invalid characters")


@dataclass(slots=True)
class ScheduleSpec:
    name: str
    kind: str               # "scan" | "sweep"
    target: str = ""        # path for scan; ignored for sweep
    frequency: str = "daily"
    time: str = "03:00"     # HH:MM, local
    quick: bool = False
    min_severity: str = "low"

    def to_dict(self) -> dict:
        return asdict(self)

    def command_args(self) -> list[str]:
        """The warden CLI args this schedule runs."""
        args = _warden_invocation()
        if self.kind == "sweep":
            args += ["sweep", "--save", "--min-severity", self.min_severity]
            if self.quick:
                args.append("--quick")
        else:
            # `--` guarantees the target is treated as a positional path even if
            # it begins with '-'; abspath so it doesn't resolve against the
            # scheduler's (unknown) working directory at run time.
            args += ["scan", "--save", "--quiet", "--min-severity", self.min_severity,
                     "--", os.path.abspath(self.target)]
        return args


class SchedulerError(Exception):
    pass


class Scheduler:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.config.ensure_dirs()
        self.registry = self.config.data_dir / "schedules.json"
        self._lock_path = self.config.data_dir / "schedules.lock"

    # -- registry ---------------------------------------------------------
    def _load(self) -> list[dict]:
        if not self.registry.exists():
            return []
        try:
            return json.loads(self.registry.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self, specs: list[dict]) -> None:
        from .storage import atomic_write_json
        atomic_write_json(self.registry, specs)

    def list(self) -> list[ScheduleSpec]:
        return [ScheduleSpec(**s) for s in self._load()]

    # -- public actions ---------------------------------------------------
    def add(self, spec: ScheduleSpec) -> str:
        _validate_name(spec.name)
        if spec.kind not in ("scan", "sweep"):
            raise SchedulerError("kind must be 'scan' or 'sweep'")
        if spec.frequency not in _FREQUENCIES:
            raise SchedulerError(f"frequency must be one of {_FREQUENCIES}")
        _validate_time(spec.time)
        try:
            Severity.parse(spec.min_severity)
        except (KeyError, ValueError):
            raise SchedulerError(f"invalid min-severity: {spec.min_severity!r}")
        if spec.kind == "scan":
            if not spec.target:
                raise SchedulerError("scan schedules need a --target path")
            _validate_target(spec.target)
            spec.target = os.path.abspath(spec.target)   # store an absolute path

        with file_lock(self._lock_path):
            specs = self._load()
            if any(s["name"] == spec.name for s in specs):
                raise SchedulerError(f"a schedule named '{spec.name}' already exists")
            detail = self._install_os_task(spec)
            specs.append(spec.to_dict())
            self._save(specs)
        return detail

    def remove(self, name: str) -> None:
        _validate_name(name)
        with file_lock(self._lock_path):
            specs = self._load()
            present = any(s["name"] == name for s in specs)
            # Always attempt the OS-level removal, even if the registry lost
            # track of it, so an orphaned task/cron line still gets cleaned up.
            self._remove_os_task(name)
            if not present:
                raise SchedulerError(f"no schedule named '{name}' (removed any orphaned OS task)")
            self._save([s for s in specs if s["name"] != name])

    # -- OS integration ---------------------------------------------------
    def _install_os_task(self, spec: ScheduleSpec) -> str:
        if IS_WINDOWS:
            return _win_create(spec)
        return _cron_sync(self._load() + [spec.to_dict()])

    def _remove_os_task(self, name: str) -> None:
        if IS_WINDOWS:
            _win_delete(name)
        else:
            _cron_sync([s for s in self._load() if s["name"] != name])


# -- invocation ----------------------------------------------------------
def _warden_invocation() -> list[str]:
    """How to launch Warden from an external scheduler."""
    if getattr(sys, "frozen", False):  # PyInstaller/Nuitka build
        return [sys.executable]
    return [sys.executable, "-m", "warden"]


def _validate_time(t: str) -> None:
    try:
        hh, mm = t.split(":")
        if not (0 <= int(hh) <= 23 and 0 <= int(mm) <= 59):
            raise ValueError
    except (ValueError, AttributeError):
        raise SchedulerError(f"time must be HH:MM (24h), got {t!r}")


# -- Windows (schtasks) --------------------------------------------------
def _schtasks_exe() -> str:
    """Absolute path to schtasks so a CWD-planted schtasks.exe can't hijack it."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    p = os.path.join(root, "System32", "schtasks.exe")
    return p if os.path.isfile(p) else "schtasks"


def _win_taskname(name: str) -> str:
    return f"\\Warden\\{name}"


def _quote_win(arg: str) -> str:
    return f'"{arg}"' if " " in arg and not arg.startswith('"') else arg


def _win_create(spec: ScheduleSpec) -> str:
    sc = {"hourly": "HOURLY", "daily": "DAILY", "weekly": "WEEKLY"}[spec.frequency]
    tr = " ".join(_quote_win(a) for a in spec.command_args())
    cmd = [_schtasks_exe(), "/create", "/tn", _win_taskname(spec.name),
           "/tr", tr, "/sc", sc, "/f"]
    if spec.frequency != "hourly":
        cmd += ["/st", spec.time]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SchedulerError(f"schtasks failed: {exc}") from exc
    if proc.returncode != 0:
        raise SchedulerError(f"schtasks error: {proc.stderr.strip() or proc.stdout.strip()}")
    return f"Windows Task Scheduler task {_win_taskname(spec.name)} created ({sc} at {spec.time})."


def _win_delete(name: str) -> None:
    subprocess.run([_schtasks_exe(), "/delete", "/tn", _win_taskname(name), "/f"],
                   capture_output=True, text=True, timeout=30)


# -- Unix (crontab) ------------------------------------------------------
def _cron_line(spec_dict: dict) -> str:
    spec = ScheduleSpec(**spec_dict)
    hh, mm = spec.time.split(":")
    if spec.frequency == "hourly":
        when = f"{int(mm)} * * * *"
    elif spec.frequency == "weekly":
        when = f"{int(mm)} {int(hh)} * * 0"
    else:  # daily
        when = f"{int(mm)} {int(hh)} * * *"
    # cron runs each line via /bin/sh, so every argument (notably the target
    # path) must be shell-quoted. Combined with _validate_target/_validate_name,
    # this closes command injection through crafted schedule data.
    cmd = " ".join(shlex.quote(a) for a in spec.command_args())
    return f"{when} {cmd}  # warden:{spec.name}"


def _cron_sync(spec_dicts: list[dict]) -> str:
    try:
        current = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    except OSError as exc:
        raise SchedulerError(f"crontab not available: {exc}") from exc

    lines = current.splitlines()
    # strip existing warden block
    out: list[str] = []
    skip = False
    for line in lines:
        if line.strip() == _CRON_BEGIN:
            skip = True
            continue
        if line.strip() == _CRON_END:
            skip = False
            continue
        if not skip:
            out.append(line)

    if spec_dicts:
        out.append(_CRON_BEGIN)
        for sd in spec_dicts:
            out.append(_cron_line(sd))
        out.append(_CRON_END)

    new_crontab = "\n".join(out).strip() + "\n"
    proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SchedulerError(f"failed to write crontab: {proc.stderr.strip()}")
    return "crontab updated with Warden schedule block."
