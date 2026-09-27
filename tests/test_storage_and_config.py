"""Tests for atomic writes and config robustness."""

import json
import os

import pytest

from warden import storage
from warden.config import Config, DEFAULT_MAX_SCAN_BYTES, MAX_SCAN_BYTES, MIN_SCAN_BYTES


def test_atomic_write_replaces_completely(tmp_path):
    p = tmp_path / "x.json"
    storage.atomic_write_json(p, {"a": 1})
    storage.atomic_write_json(p, {"a": 2, "b": 3})
    assert json.loads(p.read_text()) == {"a": 2, "b": 3}
    # no leftover temp files
    assert list(tmp_path.glob(".wtmp-*")) == []


def test_atomic_write_failure_keeps_old_file(tmp_path, monkeypatch):
    p = tmp_path / "x.json"
    storage.atomic_write_json(p, {"good": True})
    monkeypatch.setattr(storage.os, "replace",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError):
        storage.atomic_write_json(p, {"good": False})
    assert json.loads(p.read_text()) == {"good": True}      # old content intact
    assert list(tmp_path.glob(".wtmp-*")) == []             # temp cleaned up


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_config_file_is_owner_only(tmp_path):
    cfg = Config(data_dir=tmp_path)
    cfg.virustotal_api_key = "secret"
    cfg.save()
    assert (cfg.config_path.stat().st_mode & 0o077) == 0


@pytest.mark.parametrize("bad", ["huge", -5, None, 0, 10**30])
def test_malformed_max_scan_bytes_is_clamped(tmp_path, bad):
    (tmp_path / "config.json").write_text(json.dumps({"max_scan_bytes": bad}))
    cfg = Config.load(tmp_path)
    assert MIN_SCAN_BYTES <= cfg.max_scan_bytes <= MAX_SCAN_BYTES


def test_malformed_config_does_not_crash(tmp_path):
    (tmp_path / "config.json").write_text('["not", "a", "dict"]')
    cfg = Config.load(tmp_path)
    assert cfg.max_scan_bytes == DEFAULT_MAX_SCAN_BYTES
    (tmp_path / "config.json").write_text("{ broken json")
    cfg2 = Config.load(tmp_path)
    assert cfg2.use_clamav is True


def test_bad_skip_extensions_ignored(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"skip_extensions": {"a": 1}}))
    cfg = Config.load(tmp_path)
    assert isinstance(cfg.skip_extensions, set)
