"""Quarantine: isolate suspicious files safely and reversibly.

Design goals:
  * Never permanently delete on the user's behalf without explicit confirmation.
  * Never lose the user's file. The durable ordering is: write the neutralized
    blob (fsync), write the metadata sidecar (fsync), update the index, and only
    THEN delete the original. A crash at any point leaves either the untouched
    original or a fully-recorded quarantine entry - never a gap where the file
    is gone but unrecorded.
  * The stored copy must not run by accident. We XOR every byte with a fixed key
    and store it as ``<id>.qbin``. This is obfuscation to prevent accidental
    execution / AV re-detection, NOT encryption - it is trivially reversible.

Layout under ~/.warden/quarantine/ (created 0o700 on POSIX):
    <id>.qbin   -> neutralized file bytes (0o600)
    <id>.json   -> per-entry metadata; the source of truth
    index.json  -> a cache of all entries, rebuildable from the sidecars
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .models import FileResult, now_iso
from .storage import atomic_write_json, file_lock, fsync_dir, secure_dir

# Fixed XOR key used to neutralize stored bytes. Not secret - its only job is to
# ensure the quarantined copy isn't a directly runnable PE/script.
_XOR_KEY = 0x5A


@dataclass(slots=True)
class QuarantineEntry:
    id: str
    original_path: str
    quarantined_at: str
    size: int
    sha256: str | None
    verdict: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    restored: bool = False
    restored_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class QuarantineError(Exception):
    pass


class Quarantine:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.config.ensure_dirs()
        self.dir = secure_dir(self.config.quarantine_dir)
        self.index_path = self.dir / "index.json"
        self._lock_path = self.dir / "index.lock"

    # -- index io ---------------------------------------------------------
    def _load_index(self) -> list[dict[str, Any]]:
        if self.index_path.exists():
            try:
                data = json.loads(self.index_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
            except (json.JSONDecodeError, OSError):
                pass
        # Missing or corrupt index -> rebuild from the per-entry sidecars so a
        # damaged index never makes quarantined files "disappear".
        return self._rebuild_index()

    def _rebuild_index(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for jf in sorted(self.dir.glob("*.json")):
            if jf.name == "index.json":
                continue
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if isinstance(data, dict) and "id" in data:
                entries.append(data)
        if entries:
            self._save_index(entries)
        return entries

    def _save_index(self, entries: list[dict[str, Any]]) -> None:
        atomic_write_json(self.index_path, entries, mode=0o600)

    def list_entries(self) -> list[QuarantineEntry]:
        out: list[QuarantineEntry] = []
        for e in self._load_index():
            ent = _entry_from_dict(e)
            if ent is not None:
                out.append(ent)
        return out

    # -- actions ----------------------------------------------------------
    def quarantine_file(self, result: FileResult) -> QuarantineEntry:
        """Neutralize + isolate the file, then remove the original (last)."""
        src = Path(result.path)

        # Re-validate before doing anything destructive (TOCTOU / symlink).
        try:
            st = src.lstat()
        except OSError as exc:
            raise QuarantineError(f"cannot access {src}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise QuarantineError(f"refusing to quarantine a symlink: {src}")
        if not stat.S_ISREG(st.st_mode):
            raise QuarantineError(f"refusing to quarantine a non-regular file: {src}")
        # Fail CLOSED: without the scan hash we cannot prove we're quarantining
        # the bytes that were actually scanned.
        if not result.sha256:
            raise QuarantineError(f"missing scan hash for {src}; refusing to quarantine")

        entry_id = uuid.uuid4().hex[:16]
        blob_path = self.dir / f"{entry_id}.qbin"
        sidecar = self.dir / f"{entry_id}.json"

        # 1. Copy+neutralize AND hash in a SINGLE read, then verify the copied
        #    bytes are exactly the bytes that were scanned. This closes the
        #    validate-then-copy TOCTOU: the stored copy provably matches the
        #    detection, or we abort without touching the original.
        copied_sha = _xor_copy_atomic(src, blob_path, mode=0o600)
        if copied_sha != result.sha256:
            blob_path.unlink(missing_ok=True)
            raise QuarantineError(f"{src} changed since it was scanned; not quarantining")

        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(src.resolve()),
            quarantined_at=now_iso(),
            size=st.st_size,
            sha256=result.sha256,
            verdict=result.verdict.label,
            findings=[f.to_dict() for f in result.findings],
        )

        # 2. sidecar (source of truth) + 3. index, under a lock so concurrent
        #    quarantines can't lose each other's index update. Read the index
        #    BEFORE writing the sidecar, or the rebuild-from-sidecars path would
        #    see the new sidecar and we'd append a duplicate.
        with file_lock(self._lock_path):
            index = self._load_index()
            atomic_write_json(sidecar, entry.to_dict(), mode=0o600)
            index.append(entry.to_dict())
            self._save_index(index)

        # 4. remove the original LAST. If this fails, roll the record back so we
        #    never claim to have quarantined a file that's still in place.
        try:
            os.remove(src)
        except OSError as exc:
            with file_lock(self._lock_path):
                blob_path.unlink(missing_ok=True)
                sidecar.unlink(missing_ok=True)
                self._save_index([e for e in self._load_index() if e.get("id") != entry_id])
            raise QuarantineError(f"could not remove original {src}: {exc}") from exc
        return entry

    def restore(self, entry_id: str, dest: Path | None = None, *, force: bool = False) -> Path:
        """Restore a quarantined file, refusing to clobber or follow symlinks.

        ``force`` is an explicit override (overwrite an existing destination) and
        is intentionally NOT wired to the CLI or dashboard; only a library caller
        can pass it, and doing so is an informed choice to bypass the guard.
        """
        with file_lock(self._lock_path):
            index = self._load_index()
            match = next((e for e in index if e.get("id") == entry_id), None)
            if match is None:
                raise QuarantineError(f"no quarantine entry with id {entry_id}")
            blob_path = self.dir / f"{entry_id}.qbin"
            if not blob_path.exists():
                raise QuarantineError(f"quarantined data missing for {entry_id}")

            target = Path(dest) if dest else Path(match["original_path"])

            # Refuse to write through a symlink anywhere on the path, or to
            # overwrite an existing file unless the caller explicitly forces it.
            for p in [target, *target.parents]:
                if p.is_symlink():
                    raise QuarantineError(f"refusing to restore through a symlink: {p}")
            if target.exists() and not force:
                raise QuarantineError(
                    f"{target} already exists; refusing to overwrite (use force to override)")

            target.parent.mkdir(parents=True, exist_ok=True)
            _xor_copy_atomic(blob_path, target)

            match["restored"] = True
            match["restored_at"] = now_iso()
            try:
                atomic_write_json(self.dir / f"{entry_id}.json", match, mode=0o600)
            except OSError:
                pass
            self._save_index(index)
            return target

    def delete(self, entry_id: str) -> None:
        """Permanently remove a quarantined blob. Caller must confirm intent."""
        with file_lock(self._lock_path):
            index = self._load_index()
            remaining = [e for e in index if e.get("id") != entry_id]
            if len(remaining) == len(index):
                raise QuarantineError(f"no quarantine entry with id {entry_id}")
            (self.dir / f"{entry_id}.qbin").unlink(missing_ok=True)
            (self.dir / f"{entry_id}.json").unlink(missing_ok=True)
            self._save_index(remaining)


# -- helpers -------------------------------------------------------------
def _entry_from_dict(e: Any) -> QuarantineEntry | None:
    """Build a QuarantineEntry, tolerating malformed/partial index entries."""
    if not isinstance(e, dict) or "id" not in e:
        return None
    kw = {k: v for k, v in e.items() if k in QuarantineEntry.__dataclass_fields__}
    try:
        return QuarantineEntry(**kw)
    except TypeError:
        return None


def _xor_copy_atomic(src: Path, dst: Path, *, key: int = _XOR_KEY, mode: int | None = None) -> str:
    """Stream-copy src -> dst (XOR each byte), atomically + fsync'd.

    Returns the SHA-256 of the ORIGINAL bytes as they streamed, so the caller
    can prove the stored copy corresponds to exactly those bytes (closing the
    validate-then-copy TOCTOU: the hash and the copy come from one read).
    """
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    tbl = bytes(b ^ key for b in range(256))
    digest = hashlib.sha256()
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=".qtmp-")
    try:
        with os.fdopen(fd, "wb") as fout, open(src, "rb") as fin:
            for chunk in iter(lambda: fin.read(1024 * 1024), b""):
                digest.update(chunk)
                fout.write(chunk.translate(tbl))
            fout.flush()
            os.fsync(fout.fileno())
        if mode is not None and os.name != "nt":
            os.chmod(tmp, mode)
        os.replace(tmp, dst)
        fsync_dir(dst.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return digest.hexdigest()
