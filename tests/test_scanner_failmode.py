"""Tests that detection failures fail SAFE (never reported as clean)."""

import builtins
import hashlib
import types

from warden.cli import _scan_exit_code
from warden.config import Config
from warden.engines.base import ScanContext
from warden.engines.clamav import ClamAVEngine
from warden.scanner import Scanner


class RaisingEngine:
    name = "boom"

    def available(self):
        return True

    def scan(self, ctx):
        raise RuntimeError("kaboom")


def test_engine_exception_is_unknown_not_clean(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("hello")
    s = Scanner(Config(data_dir=tmp_path))
    s._engines = [RaisingEngine()]        # force the only engine to fail
    rep = s.scan_path(f)
    r = rep.results[0]
    assert r.status == "unknown"          # NOT "clean"
    assert not r.is_threat
    assert r.errored is True
    assert rep.engine_errors == 1
    assert _scan_exit_code(rep) == 2      # scripts see a non-zero "inconclusive"


def test_clean_scan_exit_zero(tmp_path):
    f = tmp_path / "ok.txt"
    f.write_text("nothing suspicious")
    rep = Scanner(Config(data_dir=tmp_path)).scan_path(f)
    assert rep.engine_errors == 0
    assert _scan_exit_code(rep) == 0


def test_clamav_error_exit_code_is_not_clean(tmp_path, monkeypatch):
    f = tmp_path / "x"
    f.write_bytes(b"data")
    eng = ClamAVEngine(enabled=True)
    eng._standalone, eng._daemon = "clamscan", None    # pretend it's installed
    monkeypatch.setattr(
        "warden.engines.clamav.subprocess.run",
        lambda *a, **k: types.SimpleNamespace(returncode=2, stdout="", stderr="db error"),
    )
    findings = eng.scan(ScanContext(f, f.stat().st_size, 1 << 20))
    assert findings and all(fd.meta.get("engine_error") for fd in findings)


def test_skip_extension_file_is_not_hashed(tmp_path):
    """Content-skipped media/VM files shouldn't be fully hashed (I/O bound)."""
    f = tmp_path / "disk.iso"
    f.write_bytes(b"not really an iso")
    rep = Scanner(Config(data_dir=tmp_path)).scan_path(f)
    assert rep.results[0].sha256 is None


def test_engine_load_error_makes_scan_degraded(tmp_path):
    """A failed-to-load engine must make the scan non-clean, not silently clean."""
    s = Scanner(Config(data_dir=tmp_path))
    s.engine_warnings = ["yara: YARA compile failed: boom"]  # simulate a broken ruleset
    f = tmp_path / "a.txt"
    f.write_text("nothing suspicious")
    rep = s.scan_path(f)
    assert rep.warnings
    assert _scan_exit_code(rep) == 2


def test_yara_load_error_distinguishes_compile_from_empty():
    from warden.config import BUNDLED_RULES_DIR
    from warden.engines.yara_engine import YaraEngine
    eng = YaraEngine([BUNDLED_RULES_DIR])
    eng._rules = None
    eng._load_error = "YARA compile failed: boom"
    assert eng.load_error is not None
    eng._load_error = "no YARA rule files found"
    assert eng.load_error is None


def test_small_file_is_read_once(tmp_path, monkeypatch):
    """A file that fits in memory is opened a single time for content + hash."""
    f = tmp_path / "x.bin"
    data = b"warden" * 1000
    f.write_bytes(data)
    ctx = ScanContext(f, len(data), 1 << 20)

    real_open, count = builtins.open, {"n": 0}

    def counting_open(p, *a, **k):
        if str(p) == str(f):
            count["n"] += 1
        return real_open(p, *a, **k)

    monkeypatch.setattr(builtins, "open", counting_open)
    assert ctx.sha256() == hashlib.sha256(data).hexdigest()
    assert ctx.data() == data
    assert count["n"] == 1
