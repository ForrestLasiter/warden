"""Safety/durability tests for quarantine: no data loss, no arbitrary write."""

import hashlib

import pytest

from warden.config import Config
from warden.models import FileResult, Finding, Severity
from warden.quarantine import Quarantine, QuarantineError


def _q(tmp_path):
    return Quarantine(Config(data_dir=tmp_path))


def _threat(path, data=b"malware"):
    return FileResult(path=str(path), size=len(data),
                      sha256=hashlib.sha256(data).hexdigest(),
                      findings=[Finding("yara", "x", Severity.HIGH)])


def _try_symlink(link, target):
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")


def test_crash_after_copy_does_not_lose_original(tmp_path, monkeypatch):
    """If deleting the original fails, the file is preserved and no entry lingers."""
    data = b"payload"
    victim = tmp_path / "bad.exe"
    victim.write_bytes(data)
    q = _q(tmp_path)

    monkeypatch.setattr("warden.quarantine.os.remove",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("locked")))
    with pytest.raises(QuarantineError):
        q.quarantine_file(_threat(victim, data))

    assert victim.exists()                 # original NOT lost
    assert victim.read_bytes() == data
    assert q.list_entries() == []          # rolled back, no dangling entry
    assert not list(tmp_path.glob("quarantine/*.qbin"))


def test_toctou_file_changed_since_scan_is_refused(tmp_path):
    victim = tmp_path / "bad.exe"
    victim.write_bytes(b"original")
    result = _threat(victim, b"original")
    victim.write_bytes(b"REPLACED after scan")   # bytes no longer match sha256
    q = _q(tmp_path)
    with pytest.raises(QuarantineError):
        q.quarantine_file(result)
    assert victim.exists()                 # untouched


def test_refuses_to_quarantine_symlink(tmp_path):
    real = tmp_path / "real.txt"
    real.write_bytes(b"secret")
    link = tmp_path / "link.exe"
    _try_symlink(link, real)
    q = _q(tmp_path)
    with pytest.raises(QuarantineError):
        q.quarantine_file(FileResult(path=str(link), findings=[Finding("yara", "x", Severity.HIGH)]))
    assert real.exists()


def test_restore_refuses_to_overwrite_existing(tmp_path):
    data = b"payload"
    victim = tmp_path / "bad.exe"
    victim.write_bytes(data)
    q = _q(tmp_path)
    entry = q.quarantine_file(_threat(victim, data))
    victim.write_bytes(b"something else is here now")   # recreated at original path
    with pytest.raises(QuarantineError):
        q.restore(entry.id)
    assert victim.read_bytes() == b"something else is here now"   # not clobbered


def test_restore_refuses_symlinked_parent(tmp_path):
    data = b"payload"
    victim = tmp_path / "sub" / "bad.exe"
    victim.parent.mkdir()
    victim.write_bytes(data)
    q = _q(tmp_path)
    entry = q.quarantine_file(_threat(victim, data))
    # Replace the parent dir with a symlink to somewhere else.
    victim.parent.rmdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _try_symlink(tmp_path / "sub", elsewhere)
    with pytest.raises(QuarantineError):
        q.restore(entry.id)
    assert not (elsewhere / "bad.exe").exists()   # nothing written through the link


def test_quarantine_fails_closed_without_scan_hash(tmp_path):
    """No scan hash -> we can't prove which bytes we're storing -> refuse."""
    victim = tmp_path / "bad.exe"
    victim.write_bytes(b"payload")
    result = FileResult(path=str(victim), findings=[Finding("yara", "x", Severity.HIGH)])
    assert result.sha256 is None
    with pytest.raises(QuarantineError):
        _q(tmp_path).quarantine_file(result)
    assert victim.exists()


def test_quarantine_aborts_when_copied_bytes_dont_match(tmp_path, monkeypatch):
    """If the bytes copied don't hash to the scanned hash, abort and keep original."""
    victim = tmp_path / "bad.exe"
    data = b"real bytes"
    victim.write_bytes(data)
    result = _threat(victim, data)
    import warden.quarantine as q
    monkeypatch.setattr(q, "_xor_copy_atomic", lambda *a, **k: "deadbeef" * 8)
    with pytest.raises(QuarantineError):
        _q(tmp_path).quarantine_file(result)
    assert victim.exists()


def test_concurrent_quarantine_keeps_both_entries(tmp_path):
    """Two concurrent quarantines must not lose each other's index update."""
    import threading
    q = Quarantine(Config(data_dir=tmp_path))
    jobs = []
    for i in range(2):
        f = tmp_path / f"m{i}.exe"
        d = f"malware-{i}".encode()
        f.write_bytes(d)
        jobs.append((f, d))
    errors = []

    def worker(f, d):
        try:
            Quarantine(Config(data_dir=tmp_path)).quarantine_file(
                FileResult(path=str(f), sha256=hashlib.sha256(d).hexdigest(),
                           findings=[Finding("yara", "x", Severity.HIGH)]))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=jd) for jd in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(q.list_entries()) == 2


def test_corrupt_index_is_rebuilt_from_sidecars(tmp_path):
    data = b"payload"
    victim = tmp_path / "bad.exe"
    victim.write_bytes(data)
    q = _q(tmp_path)
    entry = q.quarantine_file(_threat(victim, data))
    # Corrupt the index; the sidecar <id>.json still exists.
    (q.dir / "index.json").write_text("{ this is not valid json")
    entries = q.list_entries()             # must rebuild, not return empty
    assert any(e.id == entry.id for e in entries)
