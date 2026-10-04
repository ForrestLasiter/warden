"""Optional ClamAV engine.

ClamAV is the big free signature engine (millions of signatures, updated daily
via ``freshclam``). Warden works fine without it, but if the ClamAV binaries are
on PATH we use them for a massive coverage boost.

Preference order:
  1. ``clamdscan`` against a running ``clamd`` daemon  -> fast (DB stays loaded)
  2. ``clamscan``  -> slower (loads the DB every call) but no daemon needed

A signature engine is only as good as its database, so this module also reads
the installed database's version and build date and warns when it is stale.

Install on Windows: https://www.clamav.net/downloads  then run ``freshclam``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import Finding, Severity
from .base import ScanContext

# Signatures older than this are reported as stale (ClamAV publishes daily).
STALE_AFTER_DAYS = 7

_DB_DIRS = (
    "/var/lib/clamav", "/usr/local/share/clamav", "/usr/local/var/lib/clamav",
    "/opt/homebrew/var/lib/clamav", "/var/db/clamav", "/usr/share/clamav",
)
_DB_FILES = ("daily.cld", "daily.cvd", "main.cld", "main.cvd")


class ClamAVEngine:
    name = "clamav"

    def __init__(self, enabled: bool = True):
        self._enabled = enabled
        self._daemon = shutil.which("clamdscan") if enabled else None
        self._standalone = shutil.which("clamscan") if enabled else None
        self._db: dict[str, Any] | None = None
        self._db_checked = False

    def available(self) -> bool:
        return bool(self._daemon or self._standalone)

    @property
    def status(self) -> str:
        if not self._enabled:
            return "disabled in config"
        if self._daemon:
            base = f"clamdscan ({self._daemon})"
        elif self._standalone:
            base = f"clamscan ({self._standalone})"
        else:
            return "not installed (optional)"
        return f"{base}; {describe_database(self.database_info())}"

    # -- signature database ----------------------------------------------
    def database_info(self) -> dict[str, Any] | None:
        """Version and age of the installed signature database, or None if
        ClamAV isn't in use or no database could be found. Cached."""
        if not self.available():
            return None
        if not self._db_checked:
            self._db_checked = True
            binary = self._standalone or self._daemon
            self._db = find_database(binary_dir=Path(binary).parent if binary else None) \
                or _version_output_info(binary)
        return self._db

    def freshness_advisory(self) -> str | None:
        """A human sentence if the database is missing or stale, else None."""
        if not self.available():
            return None
        info = self.database_info()
        if info is None:
            return ("ClamAV is installed but its signature database could not be found - "
                    "run freshclam, or ClamAV detections will not work")
        age = info.get("age_days")
        if age is not None and age > STALE_AFTER_DAYS:
            return (f"ClamAV signatures are {age} days old (version {info.get('version', '?')}) - "
                    f"run freshclam to update")
        return None

    def scan(self, ctx: ScanContext) -> list[Finding]:
        binary = self._daemon or self._standalone
        if binary is None or ctx.in_memory:
            # In-memory content (an archive member) has no path to hand ClamAV;
            # ClamAV unpacks archives itself when it scans the outer file.
            return []
        # --no-summary keeps output to one "path: RESULT" line per file.
        cmd = [binary, "--no-summary", "--stdout", str(ctx.path)]
        if self._daemon:
            cmd.insert(1, "--fdpass")  # let clamd read the file via our fd/perms
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return [Finding.engine_error(self.name, f"ClamAV invocation failed: {exc!r}")]

        # Exit codes: 0 = clean, 1 = virus found, 2 = error.
        if proc.returncode == 1:
            sig = _parse_signature(proc.stdout)
            return [Finding(
                engine=self.name,
                name=sig or "ClamAV.Detection",
                severity=Severity.CRITICAL,
                description=f"ClamAV signature match: {sig or 'unknown'}",
                meta={"raw": proc.stdout.strip()[:400]},
            )]
        if proc.returncode != 0:
            # rc 2 (or anything else) means ClamAV could not scan the file - a
            # failure, NOT a clean result. Surface it so the file is 'unknown'.
            detail = (proc.stderr or proc.stdout or "").strip()[:200]
            return [Finding.engine_error(
                self.name, f"ClamAV error (exit {proc.returncode}): {detail}")]
        return []


def _parse_signature(stdout: str) -> str | None:
    # Line looks like:  C:\path\to\file: Win.Test.EICAR_HDB-1 FOUND
    for line in stdout.splitlines():
        line = line.strip()
        if line.endswith("FOUND"):
            body = line.rsplit(":", 1)[-1].strip()
            return body.removesuffix("FOUND").strip()
    return None


# -- database freshness --------------------------------------------------
def parse_cvd_header(head: bytes, *, now: float | None = None) -> dict[str, Any] | None:
    """Parse the 512-byte header of a ClamAV ``.cvd``/``.cld`` database.

    Format: ``ClamAV-VDB:<build time>:<version>:<sigs>:<flevel>:<md5>:<dsig>:
    <builder>:<stime>`` - colon separated, time written without colons.
    """
    if not head.startswith(b"ClamAV-VDB:"):
        return None
    fields = head[:512].decode("ascii", errors="replace").split(":")
    if len(fields) < 4:
        return None
    built: float | None = None
    if len(fields) > 8:
        m = re.match(r"\s*(\d{9,11})", fields[8])
        if m:
            built = float(m.group(1))
    if built is None:
        try:
            built = datetime.strptime(fields[1].strip(), "%d %b %Y %H-%M %z").timestamp()
        except ValueError:
            built = None
    try:
        version = int(fields[2])
        signatures = int(fields[3])
    except ValueError:
        return None
    info: dict[str, Any] = {"version": version, "signatures": signatures, "built": None, "age_days": None}
    if built is not None:
        info["built"] = datetime.fromtimestamp(built, timezone.utc).isoformat()
        info["age_days"] = max(0, int(((now if now is not None else time.time()) - built) // 86400))
    return info


def find_database(binary_dir: Path | None = None, extra_dirs: tuple[str, ...] = ()) -> dict[str, Any] | None:
    """Locate the signature database and read the freshest header we can."""
    candidates: list[Path] = [Path(d) for d in extra_dirs]
    if binary_dir is not None:
        # Windows installs keep the database beside the binaries.
        candidates += [binary_dir / "database", binary_dir.parent / "database"]
    for env in ("PROGRAMFILES", "PROGRAMDATA"):
        base = os.environ.get(env)
        if base:
            candidates += [Path(base) / "ClamAV" / "database", Path(base) / ".clamwin" / "db"]
    candidates += [Path(d) for d in _DB_DIRS]
    for d in candidates:
        for name in _DB_FILES:
            f = d / name
            try:
                with open(f, "rb") as fh:
                    info = parse_cvd_header(fh.read(512))
            except OSError:
                continue
            if info:
                info["path"] = str(f)
                return info
    return None


def _version_output_info(binary: str | None) -> dict[str, Any] | None:
    """Fallback: ``clamscan --version`` prints 'ClamAV 1.4.1/27412/<date>'."""
    if not binary:
        return None
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_version_output(out)


def parse_version_output(out: str, *, now: float | None = None) -> dict[str, Any] | None:
    parts = out.strip().split("/", 2)
    if len(parts) < 3 or not parts[1].strip().isdigit():
        return None     # no database loaded: output is just "ClamAV x.y.z"
    info: dict[str, Any] = {"version": int(parts[1]), "signatures": None, "built": None, "age_days": None}
    try:
        built = datetime.strptime(parts[2].strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        info["built"] = built.isoformat()
        info["age_days"] = max(0, int(((now if now is not None else time.time()) - built.timestamp()) // 86400))
    except ValueError:
        pass
    return info


def describe_database(info: dict[str, Any] | None) -> str:
    if info is None:
        return "signature database NOT FOUND (run freshclam)"
    age = info.get("age_days")
    text = f"signatures v{info.get('version', '?')}"
    if age is None:
        return text + ", age unknown"
    text += f", {age} day(s) old"
    return text + (" - STALE, run freshclam" if age > STALE_AFTER_DAYS else "")
