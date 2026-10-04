"""Code-signature status for executables.

Asks the operating system whether a file carries a valid publisher signature,
and who the publisher is:

  * Windows -> Authenticode, via PowerShell ``Get-AuthenticodeSignature``
  * macOS   -> ``codesign`` (Developer ID / ad-hoc)
  * Linux   -> no platform signing standard; reports ``unsupported``

This costs a subprocess per file, so the scanner only asks about files it has
already flagged (and the sweep about executables in user-writable locations).
The answer is *context* for a human reading the report: a valid signature from
a publisher you recognise makes a heuristic hit far more likely to be a false
positive. It never suppresses a finding.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

IS_WINDOWS = os.name == "nt"
IS_MACOS = os.uname().sysname == "Darwin" if hasattr(os, "uname") else False

_CACHE: dict[str, dict[str, Any]] = {}
_MAX_CACHE = 4096

# PowerShell statuses -> our normalized vocabulary.
_WIN_STATUS = {
    "Valid": "valid",
    "NotSigned": "unsigned",
    "HashMismatch": "invalid",
    "NotTrusted": "untrusted",
    "UnknownError": "invalid",
    "NotSupportedFileFormat": "unsupported",
    "Incompatible": "unsupported",
}

# A fixed script: the path arrives out-of-band in an environment variable, so a
# hostile filename can never be parsed as PowerShell code.
_PS_SCRIPT = (
    "$s = Get-AuthenticodeSignature -LiteralPath $env:WARDEN_SIGPATH; "
    "$c = $s.SignerCertificate; "
    "@{Status = \"$($s.Status)\"; Subject = \"$($c.Subject)\"; "
    "Issuer = \"$($c.Issuer)\"; Thumbprint = \"$($c.Thumbprint)\"} | ConvertTo-Json -Compress"
)


def powershell_exe() -> str:
    """Absolute path to the system PowerShell.

    SECURITY: invoking it by bare name would let Windows' executable search
    order run a `powershell.exe` planted in the current directory (which the
    sweep is often launched from, e.g. Downloads). Resolve the trusted copy.
    """
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    p = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return p if os.path.isfile(p) else "powershell"


def _result(status: str, publisher: str | None = None, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"status": status, "publisher": publisher}
    out.update({k: v for k, v in extra.items() if v})
    return out


def _common_name(subject: str) -> str | None:
    """Pull the CN out of an X.500 subject ('CN=Contoso Ltd, O=Contoso, C=US')."""
    m = re.search(r'CN=("([^"]+)"|[^,]+)', subject or "")
    if not m:
        return (subject or "").strip() or None
    return (m.group(2) or m.group(1)).strip() or None


def authenticode_info(path: Path) -> dict[str, Any]:
    """Windows Authenticode status. Assumes the caller checked the platform."""
    try:
        proc = subprocess.run(
            [powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
            capture_output=True, text=True, timeout=20,
            env={**os.environ, "WARDEN_SIGPATH": str(path)},
        )
    except (OSError, subprocess.TimeoutExpired):
        return _result("unknown")
    raw = (proc.stdout or "").strip()
    status_raw, subject, issuer, thumb = raw, "", "", ""
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            status_raw = str(data.get("Status", ""))
            subject = str(data.get("Subject", "") or "")
            issuer = str(data.get("Issuer", "") or "")
            thumb = str(data.get("Thumbprint", "") or "")
    except (json.JSONDecodeError, ValueError):
        pass  # older/odd output: treat the whole string as the bare status
    status = _WIN_STATUS.get(status_raw, "unknown")
    return _result(
        status, _common_name(subject) if subject else None,
        subject=subject[:300], issuer=_common_name(issuer) if issuer else None,
        thumbprint=thumb[:64], scheme="authenticode",
    )


def codesign_info(path: Path) -> dict[str, Any]:
    """macOS code-signature status. Assumes the caller checked the platform."""
    target = os.path.abspath(str(path))  # absolute => can't be read as an option
    codesign = "/usr/bin/codesign"
    try:
        verify = subprocess.run([codesign, "--verify", "--strict", target],
                                capture_output=True, text=True, timeout=20)
        detail = subprocess.run([codesign, "-dv", "--verbose=2", target],
                                capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return _result("unknown")
    text = (detail.stderr or "") + (detail.stdout or "")
    if "not signed at all" in text or "not signed at all" in (verify.stderr or ""):
        return _result("unsigned", scheme="codesign")
    authorities = re.findall(r"^Authority=(.+)$", text, flags=re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", text, flags=re.M)
    adhoc = "Signature=adhoc" in text
    if verify.returncode != 0:
        status = "invalid"
    elif adhoc or not authorities:
        status = "adhoc"      # runs locally, but vouches for no publisher
    else:
        status = "valid"
    return _result(
        status, authorities[0].strip() if authorities else None,
        team_id=team.group(1).strip() if team and team.group(1).strip() != "not set" else None,
        scheme="codesign",
    )


def signature_info(path: str | Path) -> dict[str, Any]:
    """Normalized signature status for a file on disk. Cached; never raises.

    ``status`` is one of: valid, unsigned, invalid, untrusted, adhoc,
    unsupported (no signing scheme on this OS / file type), unknown (the check
    itself failed).
    """
    p = Path(path)
    key = str(p)
    hit = _CACHE.get(key)
    if hit is not None:
        return hit
    try:
        if IS_WINDOWS:
            res = authenticode_info(p)
        elif IS_MACOS:
            res = codesign_info(p)
        else:
            res = _result("unsupported")
    except Exception:  # noqa: BLE001 - context only; must never break a scan
        res = _result("unknown")
    if len(_CACHE) >= _MAX_CACHE:
        _CACHE.clear()
    _CACHE[key] = res
    return res


def describe(sig: dict[str, Any] | None) -> str:
    """One-line human summary, e.g. 'valid signature - Microsoft Corporation'."""
    if not sig:
        return "signature not checked"
    status = sig.get("status", "unknown")
    publisher = sig.get("publisher")
    text = {
        "valid": "valid signature",
        "unsigned": "not signed",
        "invalid": "INVALID signature (file altered or signature broken)",
        "untrusted": "signed, but the certificate is not trusted",
        "adhoc": "ad-hoc signed (no publisher identity)",
        "unsupported": "no platform signature scheme",
        "unknown": "signature status could not be determined",
    }.get(status, status)
    return f"{text} - {publisher}" if publisher else text
