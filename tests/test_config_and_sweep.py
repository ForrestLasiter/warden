"""Tests for config persistence and the sweep command-line parser."""

from warden.config import Config
from warden.sweep import _extract_exe_path


def test_config_save_load_roundtrip(tmp_path):
    cfg = Config(data_dir=tmp_path)
    cfg.online_hash_lookup = True
    cfg.use_clamav = False
    cfg.max_scan_bytes = 5_000_000        # within [MIN_SCAN_BYTES, MAX_SCAN_BYTES]
    cfg.save()

    loaded = Config.load(tmp_path)
    assert loaded.online_hash_lookup is True
    assert loaded.use_clamav is False
    assert loaded.max_scan_bytes == 5_000_000


def test_config_save_does_not_write_vt_key(tmp_path):
    """The VirusTotal key must never be persisted in config.json (plaintext)."""
    import json
    cfg = Config(data_dir=tmp_path)
    cfg.virustotal_api_key = "leftover-plaintext-key"
    cfg.save()
    on_disk = json.loads((tmp_path / "config.json").read_text())
    assert "virustotal_api_key" not in on_disk


def test_config_defaults_when_missing(tmp_path):
    cfg = Config.load(tmp_path / "does-not-exist")
    assert cfg.online_hash_lookup is False
    assert cfg.virustotal_api_key == ""
    assert cfg.use_clamav is True


def test_config_derived_dirs(tmp_path):
    cfg = Config(data_dir=tmp_path)
    assert cfg.quarantine_dir == tmp_path / "quarantine"
    assert cfg.cache_dir == tmp_path / "cache"
    cfg.ensure_dirs()
    assert cfg.quarantine_dir.is_dir() and cfg.cache_dir.is_dir()


def test_extract_exe_path_quoted(tmp_path):
    exe = tmp_path / "my app.exe"
    exe.write_bytes(b"MZ")
    cmd = f'"{exe}" --flag value'
    assert _extract_exe_path(cmd) == exe


def test_extract_exe_path_unquoted(tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"MZ")
    assert _extract_exe_path(f"{exe} /c echo hi") == exe


def test_extract_exe_path_empty():
    assert _extract_exe_path("") is None
    assert _extract_exe_path("   ") is None
