"""Optional ClamAV engine.

ClamAV is the big free signature engine (millions of signatures, updated daily
via ``freshclam``). Warden works fine without it, but if the ClamAV binaries are
on PATH we use them for a massive coverage boost.

Preference order:
  1. ``clamdscan`` against a running ``clamd`` daemon  -> fast (DB stays loaded)
  2. ``clamscan``  -> slower (loads the DB every call) but no daemon needed

Install on Windows: https://www.clamav.net/downloads  then run ``freshclam``.
"""

from __future__ import annotations

import shutil
import subprocess

from ..models import Finding, Severity
from .base import ScanContext


class ClamAVEngine:
    name = "clamav"

    def __init__(self, enabled: bool = True):
        self._enabled = enabled
        self._daemon = shutil.which("clamdscan") if enabled else None
        self._standalone = shutil.which("clamscan") if enabled else None

    def available(self) -> bool:
        return bool(self._daemon or self._standalone)

    @property
    def status(self) -> str:
        if not self._enabled:
            return "disabled in config"
        if self._daemon:
            return f"clamdscan ({self._daemon})"
        if self._standalone:
            return f"clamscan ({self._standalone})"
        return "not installed (optional)"

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
