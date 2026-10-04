"""Tests for atomic writes and config robustness."""

import json
import os

import pytest

from warden import storage
from warden.config import DEFAULT_MAX_SCAN_BYTES, MAX_SCAN_BYTES, MIN_SCAN_BYTES, Config


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


def test_string_booleans_are_coerced(tmp_path):
    (tmp_path / "config.json").write_text(
        json.dumps({"use_clamav": "false", "follow_symlinks": "true",
                    "online_hash_lookup": "no"}))
    cfg = Config.load(tmp_path)
    assert cfg.use_clamav is False
    assert cfg.follow_symlinks is True
    assert cfg.online_hash_lookup is False


def test_file_lock_is_exclusive(tmp_path):
    import threading
    import time

    from warden import storage
    lock = tmp_path / "x.lock"
    order = []

    def worker(tag, hold):
        with storage.file_lock(lock):
            order.append(f"{tag}-in")
            time.sleep(hold)
            order.append(f"{tag}-out")

    t1 = threading.Thread(target=worker, args=("a", 0.2))
    t2 = threading.Thread(target=worker, args=("b", 0.0))
    t1.start()
    time.sleep(0.05)
    t2.start()
    t1.join()
    t2.join()
    # b must not enter until a has left (no interleaving).
    assert order in (["a-in", "a-out", "b-in", "b-out"],
                     ["b-in", "b-out", "a-in", "a-out"])
