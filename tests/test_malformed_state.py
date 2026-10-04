"""P0 #10: malformed persistent-state files must degrade, not crash."""

import json

from warden.config import Config
from warden.quarantine import Quarantine
from warden.scheduler import Scheduler


def test_scheduler_list_skips_malformed_entries(tmp_path):
    reg = tmp_path / "schedules.json"
    reg.write_text(json.dumps([
        {"name": "good", "kind": "sweep", "frequency": "daily", "time": "03:00",
         "quick": False, "min_severity": "low", "target": ""},
        {"name": "bad-extra", "kind": "sweep", "bogus_field": 123},   # extra key
        "not-a-dict",
        {"no_name": True},
    ]))
    specs = Scheduler(Config(data_dir=tmp_path)).list()
    names = [s.name for s in specs]
    assert "good" in names
    # bad-extra has an unknown key but known fields are fine -> kept after filtering
    assert "not-a-dict" not in names


def test_scheduler_corrupt_registry_is_empty(tmp_path):
    (tmp_path / "schedules.json").write_text("{ broken")
    assert Scheduler(Config(data_dir=tmp_path)).list() == []


def test_quarantine_list_skips_malformed_index(tmp_path):
    q = Quarantine(Config(data_dir=tmp_path))
    q.index_path.write_text(json.dumps([
        {"id": "aaa", "original_path": "/x", "quarantined_at": "t", "size": 1,
         "sha256": None, "verdict": "High"},
        {"missing": "id"},
        "nope",
    ]))
    entries = q.list_entries()
    assert [e.id for e in entries] == ["aaa"]


def test_quarantine_corrupt_index_rebuilds(tmp_path):
    q = Quarantine(Config(data_dir=tmp_path))
    # a valid sidecar exists but the index is garbage
    (q.dir / "bbb.json").write_text(json.dumps(
        {"id": "bbb", "original_path": "/y", "quarantined_at": "t", "size": 2,
         "sha256": None, "verdict": "Critical"}))
    q.index_path.write_text("}{ not json")
    assert any(e.id == "bbb" for e in q.list_entries())
