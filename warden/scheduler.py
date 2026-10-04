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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import Config
from .models import Severity, now_iso
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
    created: str = ""       # ISO timestamp; lets diagnostics spot a schedule that never ran

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


@dataclass(slots=True)
class ScheduleDiagnosis:
    """Health of one registered schedule, as found by ``Scheduler.diagnose``."""
    name: str
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "problems": self.problems,
                "notes": self.notes, "info": self.info}


# Named at module level because Scheduler defines a method called ``list``.
DiagnosisResult = tuple[list[ScheduleDiagnosis], list[str]]

# Windows Task Scheduler result codes that aren't failures.
_TASK_NOT_YET_RUN = 0x41303
_TASK_RUNNING = 0x41301
_PERIOD_SECONDS = {"hourly": 3600, "daily": 86400, "weekly": 7 * 86400}


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
        out: list[ScheduleSpec] = []
        for s in self._load():
            if not isinstance(s, dict) or "name" not in s:
                continue
            kw = {k: v for k, v in s.items() if k in ScheduleSpec.__dataclass_fields__}
            try:
                out.append(ScheduleSpec(**kw))
            except TypeError:
                continue  # malformed entry - skip rather than crash
        return out

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
            raise SchedulerError(f"invalid min-severity: {spec.min_severity!r}") from None
        if spec.kind == "scan":
            if not spec.target:
                raise SchedulerError("scan schedules need a --target path")
            _validate_target(spec.target)
            spec.target = os.path.abspath(spec.target)   # store an absolute path

        spec.created = spec.created or now_iso()
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

    # -- diagnostics ------------------------------------------------------
    def diagnose(self) -> DiagnosisResult:
        """Check every registered schedule against what the OS will really run.

        Returns ``(per_schedule, general_problems)``. A schedule that looks
        fine in ``schedule list`` can still be silently dead: the OS task was
        deleted, it points at a Warden binary that has since moved, its target
        folder is gone, or the cron daemon isn't running. This finds those.
        """
        specs = self.list()
        general: list[str] = []
        history = _last_history_by_kind(self.config)
        if IS_WINDOWS:
            os_names = _win_list_tasks()
        else:
            cron_text, cron_err = _cron_current()
            if cron_err:
                general.append(cron_err)
            os_names = _cron_marked_names(cron_text)
            if specs and sys.platform.startswith("linux") and not _cron_daemon_running():
                general.append("no cron daemon (cron/crond) appears to be running - "
                               "scheduled scans will not start")

        out: list[ScheduleDiagnosis] = []
        for spec in specs:
            d = ScheduleDiagnosis(name=spec.name)
            args = spec.command_args()
            d.info.update(kind=spec.kind, frequency=spec.frequency, runs=" ".join(args))
            if not os.path.isfile(args[0]):
                d.problems.append(f"the Warden program it would run no longer exists: {args[0]}")
            if spec.kind == "scan" and not os.path.exists(spec.target):
                d.problems.append(f"scan target no longer exists: {spec.target}")

            if IS_WINDOWS:
                _diagnose_windows(spec, d, args)
            else:
                _diagnose_cron(spec, d, cron_text)

            last = history.get(spec.kind)
            d.info["last_recorded_run"] = last or None
            _check_overdue(spec, d, last)
            out.append(d)

        known = {s.name for s in specs}
        for name in sorted(set(os_names) - known):
            general.append(f"orphaned OS task '{name}' is not in Warden's registry "
                           f"(remove it with: warden schedule remove {name})")
        return out, general

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


# -- diagnostics helpers -------------------------------------------------
def _last_history_by_kind(config: Config) -> dict[str, str]:
    from .history import History
    latest: dict[str, str] = {}
    try:
        for e in History(config).list(limit=200):
            if e.kind not in latest and e.when:
                latest[e.kind] = e.when
    except OSError:
        pass
    return latest


def _parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _check_overdue(spec: ScheduleSpec, d: ScheduleDiagnosis, last: str | None) -> None:
    """Flag a schedule that has existed for two full periods with no saved run."""
    created = _parse_iso(spec.created)
    if created is None:
        return
    period = _PERIOD_SECONDS.get(spec.frequency, 86400)
    now = datetime.now(timezone.utc)
    if (now - created).total_seconds() < 2 * period:
        return
    last_dt = _parse_iso(last) if last else None
    if last_dt is None or last_dt < created:
        d.problems.append(f"no {spec.kind} has been recorded in history since this was scheduled "
                          f"(expected {spec.frequency})")
    elif (now - last_dt).total_seconds() > 3 * period:
        d.notes.append(f"last recorded {spec.kind} was {last_dt.date().isoformat()} - "
                       f"overdue for a {spec.frequency} schedule")


def _describe_result(code: int) -> tuple[str, bool]:
    """(text, is_problem) for a Task Scheduler 'last result' code."""
    if code == 0:
        return "finished: clean", False
    if code == 1:
        return "finished: THREATS FOUND - review with 'warden history list'", False
    if code == 2:
        return "finished: scan incomplete (coverage gaps)", False
    if code == _TASK_NOT_YET_RUN:
        return "has not run yet", False
    if code == _TASK_RUNNING:
        return "running now", False
    return f"failed to run (result code {code:#x})", True


def _diagnose_windows(spec: ScheduleSpec, d: ScheduleDiagnosis, args: list[str]) -> None:
    info = _win_task_info(spec.name)
    if info is None:
        d.problems.append(f"Task Scheduler has no task {_win_taskname(spec.name)} "
                          f"(re-create it: remove and add the schedule again)")
        return
    state = str(info.get("State", ""))
    d.info.update(state=state, last_run=info.get("LastRunTime") or None,
                  next_run=info.get("NextRunTime") or None)
    if state.lower() == "disabled":
        d.problems.append("the task is disabled in Task Scheduler")
    execute = str(info.get("Execute", "")).strip().strip('"')
    if execute and os.path.normcase(execute) != os.path.normcase(args[0]):
        d.problems.append(f"the task runs {execute}, not this Warden install ({args[0]})")
    try:
        text, bad = _describe_result(int(info.get("LastTaskResult", 0)))
    except (TypeError, ValueError):
        text, bad = "unknown", False
    d.info["last_result"] = text
    if bad:
        d.problems.append(f"last run {text}")


def _diagnose_cron(spec: ScheduleSpec, d: ScheduleDiagnosis, cron_text: str) -> None:
    expected = _cron_line(spec.to_dict())
    marker = f"# warden:{spec.name}"
    lines = [ln.strip() for ln in cron_text.splitlines()]
    if expected in lines:
        d.info["state"] = "installed"
    elif any(ln.endswith(marker) for ln in lines):
        d.info["state"] = "modified"
        d.problems.append("the crontab entry differs from the registered schedule "
                          "(edited by hand, or Warden moved) - remove and re-add it")
    else:
        d.info["state"] = "missing"
        d.problems.append("no crontab entry for this schedule (re-create it: remove and add again)")


def _cron_current() -> tuple[str, str | None]:
    try:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", f"crontab is not available: {exc}"
    return (proc.stdout if proc.returncode == 0 else ""), None


def _cron_marked_names(cron_text: str) -> list[str]:
    out: list[str] = []
    for line in cron_text.splitlines():
        m = re.search(r"#\s*warden:([A-Za-z0-9_-]{1,64})\s*$", line)
        if m:
            out.append(m.group(1))
    return out


def _cron_daemon_running() -> bool:
    try:
        import psutil
    except Exception:  # noqa: BLE001
        return True   # can't tell - don't raise a false alarm
    try:
        names = {(p.info.get("name") or "").lower() for p in psutil.process_iter(["name"])}
    except Exception:  # noqa: BLE001
        return True
    return bool(names & {"cron", "crond", "fcron", "cronie", "anacron", "systemd-cron"})


_PS_TASK_INFO = (
    "$t = Get-ScheduledTask -TaskPath '\\Warden\\' -TaskName $env:WARDEN_TASK -ErrorAction Stop; "
    "$i = $t | Get-ScheduledTaskInfo; "
    "$fmt = { param($d) if ($d) { $d.ToString('yyyy-MM-dd HH:mm') } else { '' } }; "
    "@{State = \"$($t.State)\"; Execute = \"$($t.Actions[0].Execute)\"; "
    "Arguments = \"$($t.Actions[0].Arguments)\"; LastRunTime = (& $fmt $i.LastRunTime); "
    "NextRunTime = (& $fmt $i.NextRunTime); LastTaskResult = [int64]$i.LastTaskResult} "
    "| ConvertTo-Json -Compress"
)
_PS_TASK_LIST = (
    "Get-ScheduledTask -TaskPath '\\Warden\\' -ErrorAction SilentlyContinue "
    "| ForEach-Object { $_.TaskName }"
)


def _powershell(script: str, env: dict[str, str] | None = None) -> str | None:
    from .signature import powershell_exe
    try:
        proc = subprocess.run(
            [powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, **(env or {})})
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _win_task_info(name: str) -> dict[str, Any] | None:
    # The (already regex-validated) name still travels out-of-band, never in
    # the script text.
    out = _powershell(_PS_TASK_INFO, {"WARDEN_TASK": name})
    if not out:
        return None
    try:
        data = json.loads(out.strip())
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _win_list_tasks() -> list[str]:
    out = _powershell(_PS_TASK_LIST)
    if not out:
        return []
    return [ln.strip() for ln in out.splitlines() if _NAME_RE.match(ln.strip())]


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
        raise SchedulerError(f"time must be HH:MM (24h), got {t!r}") from None


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
