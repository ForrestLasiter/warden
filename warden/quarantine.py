"""Quarantine: isolate suspicious files safely and reversibly.

Design goals:
  * Never permanently delete on the user's behalf without explicit confirmation.
  * Never lose the user's file. The durable ordering is: write the neutralized
    blob (fsync), write the metadata sidecar (fsync), update the index, and only
    THEN delete the original. A crash at any point leaves either the untouched
    original or a fully-recorded quarantine entry - never a gap where the file
    is gone but unrecorded.
  * The stored copy must not run by accident. By default we XOR every byte with
    a fixed key and store it as ``<id>.qbin``. This is obfuscation to prevent
    accidental execution / AV re-detection, NOT encryption - it is trivially
    reversible.
  * Optionally (``quarantine_encryption``), the copy is instead sealed with
    AES-256-GCM as ``<id>.qenc``: confidential *and* tamper-evident. The key is
    random, per machine, and lives in the OS secret store.
  * What comes back out is what went in. Every restore, rescan and export
    re-hashes the decoded bytes against the hash recorded at quarantine time and
    refuses on a mismatch.

Layout under ~/.warden/quarantine/ (created 0o700 on POSIX):
    <id>.qbin   -> XOR-neutralized file bytes (0o600), or
    <id>.qenc   -> AES-256-GCM sealed file bytes (0o600)
    <id>.json   -> per-entry metadata; the source of truth
    index.json  -> a cache of all entries, rebuildable from the sidecars

Export bundles (``warden quarantine export``) are zip files holding the entry's
metadata and its *XOR-neutralized* payload - never the live file - optionally
wrapped in password-based AES-256-GCM (scrypt) for sending a sample to someone.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets as _stdlib_secrets
import stat
import tempfile
import time
import uuid
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import audit
from .config import Config
from .models import FileResult, now_iso
from .storage import atomic_write_json, file_lock, fsync_dir, secure_dir

# Fixed XOR key used to neutralize stored bytes. Not secret - its only job is to
# ensure the quarantined copy isn't a directly runnable PE/script.
_XOR_KEY = 0x5A
_XOR_TABLE = bytes(b ^ _XOR_KEY for b in range(256))

_CHUNK = 1024 * 1024
_ENC_MAGIC = b"WQE1"            # sealed blob: magic | 16-byte salt | chunks
_BUNDLE_MAGIC = b"WQX1"         # password-wrapped export: magic | 16-byte salt | chunks
_TAG = 16
_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_KEY_NAME = "quarantine_key"
MAX_RESCAN_BYTES = 256 * 1024 * 1024
MAX_IMPORT_BYTES = 8 * 1024 * 1024 * 1024

# Warden uses only modern primitives (Ed25519, AES-GCM, HKDF, scrypt). Telling
# the library not to load OpenSSL's "legacy" provider keeps it from failing at
# import on machines where that optional module isn't present.
os.environ.setdefault("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", "1")

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    _CRYPTO = True
    _CRYPTO_ERROR = ""
except Exception as _exc:  # pragma: no cover - cryptography is a declared dependency
    _CRYPTO = False
    # Keep the reason: "is it missing, or did it fail to load?" is the first
    # question when this is hit inside a packaged build.
    _CRYPTO_ERROR = f"{type(_exc).__name__}: {_exc}"


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
    encrypted: bool = False           # sealed with AES-256-GCM instead of XOR
    imported: bool = False            # came from an export bundle (its path is untrusted)
    last_rescan: dict[str, Any] | None = None

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
                    # Only well-formed entries: every caller may then rely on
                    # each one being a dict with a string id.
                    return [e for e in data if isinstance(e, dict) and isinstance(e.get("id"), str)]
            except (ValueError, OSError):
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
            except (ValueError, OSError):
                continue
            if isinstance(data, dict) and isinstance(data.get("id"), str):
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

    def _find(self, index: list[dict[str, Any]], entry_id: str) -> dict[str, Any]:
        match = next((e for e in index if isinstance(e, dict) and e.get("id") == entry_id), None)
        if match is None:
            raise QuarantineError(f"no quarantine entry with id {entry_id}")
        return match

    def _blob(self, entry_id: str) -> tuple[Path, bool]:
        """(path, is_encrypted) of an entry's stored bytes."""
        # The id becomes part of a file name: only our own id shape is allowed,
        # so a crafted id can never reach outside the quarantine directory.
        if not _ID_RE.match(str(entry_id)):
            raise QuarantineError(f"no quarantine entry with id {entry_id}")
        enc = self.dir / f"{entry_id}.qenc"
        if enc.exists():
            return enc, True
        plain = self.dir / f"{entry_id}.qbin"
        if plain.exists():
            return plain, False
        raise QuarantineError(f"quarantined data missing for {entry_id}")

    def _plain_chunks(self, entry_id: str) -> Iterator[bytes]:
        """The original file bytes of an entry, decoded as a stream."""
        path, encrypted = self._blob(entry_id)
        if encrypted:
            yield from _open_sealed(path, _file_key(self._master_key(create=False), path, entry_id),
                                    entry_id.encode())
        else:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(_CHUNK), b""):
                    yield chunk.translate(_XOR_TABLE)

    def _master_key(self, *, create: bool) -> bytes:
        return _master_key(create=create)

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
        encrypt = bool(self.config.quarantine_encryption)
        blob_path = self.dir / f"{entry_id}.{'qenc' if encrypt else 'qbin'}"
        sidecar = self.dir / f"{entry_id}.json"

        # 1. Copy+neutralize AND hash in a SINGLE read, then verify the copied
        #    bytes are exactly the bytes that were scanned. This closes the
        #    validate-then-copy TOCTOU: the stored copy provably matches the
        #    detection, or we abort without touching the original.
        if encrypt:
            copied_sha = _seal_copy_atomic(src, blob_path, self._master_key(create=True),
                                           entry_id, mode=0o600)
        else:
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
            encrypted=encrypt,
        )
        self._record(entry)

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
        self._audit("quarantine.add", entry.to_dict())
        return entry

    def _audit(self, event: str, entry: dict[str, Any], **extra: Any) -> None:
        audit.record(event, self.config, id=entry.get("id"), path=entry.get("original_path"),
                     sha256=entry.get("sha256"), verdict=entry.get("verdict"),
                     encrypted=bool(entry.get("encrypted")), **extra)

    def _record(self, entry: QuarantineEntry) -> None:
        # 2. sidecar (source of truth) + 3. index, under a lock so concurrent
        #    quarantines can't lose each other's index update. Read the index
        #    BEFORE writing the sidecar, or the rebuild-from-sidecars path would
        #    see the new sidecar and we'd append a duplicate.
        with file_lock(self._lock_path):
            index = self._load_index()
            atomic_write_json(self.dir / f"{entry.id}.json", entry.to_dict(), mode=0o600)
            index.append(entry.to_dict())
            self._save_index(index)

    def restore(self, entry_id: str, dest: Path | None = None, *, force: bool = False) -> Path:
        """Restore a quarantined file, refusing to clobber or follow symlinks.

        ``force`` is an explicit override (overwrite an existing destination) and
        is intentionally NOT wired to the CLI or dashboard; only a library caller
        can pass it, and doing so is an informed choice to bypass the guard.

        The decoded bytes are verified against the hash recorded at quarantine
        time before anything appears at the destination.
        """
        with file_lock(self._lock_path):
            index = self._load_index()
            match = self._find(index, entry_id)
            self._blob(entry_id)        # fail early if the data is gone

            if dest is None and match.get("imported"):
                # An imported bundle's "original path" was written by whoever
                # made the bundle; never let it choose where a file lands here.
                raise QuarantineError(
                    "this item was imported from a bundle; choose where to restore it with --to")
            original = match.get("original_path")
            if dest is None and (not isinstance(original, str) or not original):
                raise QuarantineError("this item has no recorded path; choose one with --to")
            target = Path(dest) if dest else Path(str(original))

            # Refuse to write through a symlink anywhere on the path, or to
            # overwrite an existing file unless the caller explicitly forces it.
            for p in [target, *target.parents]:
                if p.is_symlink():
                    raise QuarantineError(f"refusing to restore through a symlink: {p}")
            if target.exists() and not force:
                raise QuarantineError(
                    f"{target} already exists; refusing to overwrite (use force to override)")

            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                expected = match.get("sha256")
                _write_verified(self._plain_chunks(entry_id), target,
                                expected if isinstance(expected, str) else None, clobber=force)
            except FileExistsError:
                raise QuarantineError(
                    f"{target} already exists; refusing to overwrite (use force to override)") from None

            match["restored"] = True
            match["restored_at"] = now_iso()
            try:
                atomic_write_json(self.dir / f"{entry_id}.json", match, mode=0o600)
            except OSError:
                pass
            self._save_index(index)
            self._audit("quarantine.restore", match, restored_to=str(target), forced=bool(force))
            return target

    def delete(self, entry_id: str) -> None:
        """Permanently remove a quarantined blob. Caller must confirm intent."""
        with file_lock(self._lock_path):
            index = self._load_index()
            remaining = [e for e in index if e.get("id") != entry_id]
            if len(remaining) == len(index):
                raise QuarantineError(f"no quarantine entry with id {entry_id}")
            gone = next(e for e in index if e.get("id") == entry_id)
            self._unlink_files(entry_id)
            self._save_index(remaining)
        self._audit("quarantine.delete", gone)

    def _unlink_files(self, entry_id: str) -> None:
        if not _ID_RE.match(str(entry_id)):
            return      # never build a path from an id we didn't mint
        for suffix in ("qbin", "qenc", "json"):
            (self.dir / f"{entry_id}.{suffix}").unlink(missing_ok=True)

    # -- rescan -----------------------------------------------------------
    def read_bytes(self, entry_id: str, *, max_bytes: int = MAX_RESCAN_BYTES) -> bytes:
        """The original content of a quarantined item, in memory only, verified
        against its recorded hash."""
        with file_lock(self._lock_path):
            match = self._find(self._load_index(), entry_id)
        digest = hashlib.sha256()
        buf = bytearray()
        for chunk in self._plain_chunks(entry_id):
            digest.update(chunk)
            buf += chunk
            if len(buf) > max_bytes:
                raise QuarantineError(
                    f"quarantined item is larger than {max_bytes // (1024 * 1024)} MiB; "
                    f"too large to re-scan in memory")
        expected = match.get("sha256")
        if expected and digest.hexdigest() != expected:
            raise QuarantineError(f"stored data for {entry_id} does not match its recorded hash "
                                  f"(damaged or altered)")
        return bytes(buf)

    def rescan(self, entry_id: str, scanner: Any = None) -> FileResult:
        """Re-check a quarantined item against the *current* rules, in memory.

        Detections improve and false positives get fixed, so the verdict from
        the day a file was quarantined may no longer hold. Nothing is written
        outside the quarantine folder and the item stays isolated.
        """
        with file_lock(self._lock_path):
            match = dict(self._find(self._load_index(), entry_id))
        data = self.read_bytes(entry_id)
        if scanner is None:
            from .scanner import Scanner
            scanner = Scanner(self.config)
        name = Path(str(match.get("original_path") or entry_id)).name or entry_id
        result = scanner.scan_bytes(name, data)
        summary = {"when": now_iso(), "verdict": result.verdict.label,
                   "threat": result.is_threat, "status": result.status,
                   "findings": [f.name for f in result.findings][:20]}
        with file_lock(self._lock_path):
            index = self._load_index()
            entry = self._find(index, entry_id)
            entry["last_rescan"] = summary
            try:
                atomic_write_json(self.dir / f"{entry_id}.json", entry, mode=0o600)
            except OSError:
                pass
            self._save_index(index)
        self._audit("quarantine.rescan", match, still_threat=result.is_threat,
                    current_verdict=result.verdict.label)
        return result

    # -- cleanup ----------------------------------------------------------
    def purge(self, *, older_than_days: float | None = None, restored_only: bool = False,
              everything: bool = False, dry_run: bool = False) -> list[QuarantineEntry]:
        """Permanently delete quarantined items by age and/or state.

        Selection is conservative: with no criteria nothing is selected. Callers
        (the CLI) must obtain the user's confirmation - this is irreversible.
        """
        if not everything and older_than_days is None and not restored_only:
            return []
        cutoff = None if older_than_days is None else time.time() - older_than_days * 86400
        selected: list[QuarantineEntry] = []
        with file_lock(self._lock_path):
            index = self._load_index()
            keep: list[dict[str, Any]] = []
            for raw in index:
                entry = _entry_from_dict(raw)
                if entry is None:
                    keep.append(raw)
                    continue
                hit = True
                if not everything:
                    if restored_only and not entry.restored:
                        hit = False
                    if cutoff is not None:
                        when = _timestamp(entry.quarantined_at)
                        if when is None or when > cutoff:
                            hit = False
                if hit:
                    selected.append(entry)
                else:
                    keep.append(raw)
            if not dry_run and selected:
                for entry in selected:
                    self._unlink_files(entry.id)
                self._save_index(keep)
        if not dry_run:
            for entry in selected:
                self._audit("quarantine.delete", entry.to_dict(), reason="purge",
                            older_than_days=older_than_days, restored_only=restored_only)
        return selected

    # -- export / import --------------------------------------------------
    def export(self, entry_id: str, out_path: Path, *, password: str | None = None) -> Path:
        """Write a portable bundle of one quarantined item.

        The payload inside is XOR-neutralized (never the runnable file) and is
        verified against the recorded hash while it is written. With a
        ``password`` the whole bundle is additionally sealed with AES-256-GCM
        under a scrypt-derived key.
        """
        out_path = Path(out_path)
        if out_path.exists():
            raise QuarantineError(f"{out_path} already exists; refusing to overwrite")
        with file_lock(self._lock_path):
            match = dict(self._find(self._load_index(), entry_id))
        meta = {k: match.get(k) for k in ("original_path", "quarantined_at", "size", "sha256",
                                          "verdict", "findings")}
        meta.update({"bundle_format": 1, "exported_at": now_iso(), "id": entry_id})

        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(out_path.parent), prefix=".wq-export-")
        os.close(fd)
        try:
            digest = hashlib.sha256()
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("entry.json", json.dumps(meta, indent=2))
                with zf.open("payload.xor", "w", force_zip64=True) as dst:
                    for chunk in self._plain_chunks(entry_id):
                        digest.update(chunk)
                        dst.write(chunk.translate(_XOR_TABLE))
            if meta.get("sha256") and digest.hexdigest() != meta["sha256"]:
                raise QuarantineError(f"stored data for {entry_id} does not match its recorded "
                                      f"hash (damaged or altered); not exporting")
            if password:
                sealed = tmp + ".sealed"
                try:
                    _password_seal(Path(tmp), Path(sealed), password)
                    os.replace(sealed, tmp)
                finally:
                    Path(sealed).unlink(missing_ok=True)
            if os.name != "nt":
                os.chmod(tmp, 0o600)
            _publish(Path(tmp), out_path, clobber=False)
        except FileExistsError:
            raise QuarantineError(f"{out_path} already exists; refusing to overwrite") from None
        finally:
            Path(tmp).unlink(missing_ok=True)
        self._audit("quarantine.export", match, bundle=str(out_path),
                    password_protected=bool(password))
        return out_path

    def import_bundle(self, bundle: Path, *, password: str | None = None) -> QuarantineEntry:
        """Add an exported bundle to this machine's quarantine.

        The bundle is untrusted input: its payload must hash to the value in its
        own metadata, its declared size is enforced while reading, and the
        resulting entry is marked ``imported`` so its recorded path can never be
        used as a restore destination without the user choosing one.
        """
        bundle = Path(bundle)
        try:
            with open(bundle, "rb") as fh:
                magic = fh.read(4)
        except OSError as exc:
            raise QuarantineError(f"cannot read {bundle}: {exc}") from exc

        workdir = Path(tempfile.mkdtemp(dir=str(self.dir), prefix=".import-"))
        try:
            zip_path = bundle
            if magic == _BUNDLE_MAGIC:
                if not password:
                    raise QuarantineError("this bundle is password-protected; pass --password")
                zip_path = workdir / "bundle.zip"
                _password_open(bundle, zip_path, password)
            try:
                zf = zipfile.ZipFile(zip_path)
            except (zipfile.BadZipFile, OSError):
                raise QuarantineError("not a Warden quarantine bundle") from None
            with zf:
                try:
                    if zf.getinfo("entry.json").file_size > 1024 * 1024:
                        raise QuarantineError("quarantine bundle has invalid metadata")
                    meta = json.loads(zf.read("entry.json").decode("utf-8"))
                    info = zf.getinfo("payload.xor")
                except (KeyError, ValueError, UnicodeDecodeError, zipfile.BadZipFile):
                    raise QuarantineError("not a Warden quarantine bundle") from None
                if not isinstance(meta, dict) or meta.get("bundle_format") != 1:
                    raise QuarantineError("unsupported quarantine bundle format")
                sha = meta.get("sha256")
                size = meta.get("size")
                if (not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)
                        or isinstance(size, bool) or not isinstance(size, int)
                        or not (0 <= size <= MAX_IMPORT_BYTES)):
                    raise QuarantineError("quarantine bundle has invalid metadata")

                entry_id = uuid.uuid4().hex[:16]
                encrypt = bool(self.config.quarantine_encryption)
                blob_path = self.dir / f"{entry_id}.{'qenc' if encrypt else 'qbin'}"
                staged = workdir / "payload"
                digest = hashlib.sha256()
                written = 0
                try:
                    with zf.open(info) as src, open(staged, "wb") as dst:
                        for chunk in iter(lambda: src.read(_CHUNK), b""):
                            written += len(chunk)
                            if written > size:
                                raise QuarantineError("bundle payload is larger than it declares")
                            plain = chunk.translate(_XOR_TABLE)
                            digest.update(plain)
                            dst.write(plain if encrypt else chunk)
                except (zipfile.BadZipFile, OSError, EOFError) as exc:
                    raise QuarantineError(f"bundle payload is unreadable: {exc}") from exc
                if written != size or digest.hexdigest() != sha:
                    raise QuarantineError("bundle payload does not match its recorded hash")

            if encrypt:
                # ``staged`` briefly holds the plain bytes inside the 0700
                # quarantine dir; seal it and it is removed with the workdir.
                _seal_copy_atomic(staged, blob_path, self._master_key(create=True), entry_id, mode=0o600)
            else:
                if os.name != "nt":
                    os.chmod(staged, 0o600)
                os.replace(staged, blob_path)

            findings = meta.get("findings")
            entry = QuarantineEntry(
                id=entry_id,
                original_path=_clean_text(meta.get("original_path"), 1024),
                quarantined_at=now_iso(),
                size=size, sha256=sha,
                verdict=_clean_text(meta.get("verdict"), 32) or "Unknown",
                findings=[f for f in findings if isinstance(f, dict)][:100] if isinstance(findings, list) else [],
                encrypted=encrypt, imported=True,
            )
            self._record(entry)
            self._audit("quarantine.import", entry.to_dict(), bundle=str(bundle))
            return entry
        finally:
            for f in workdir.glob("*"):
                f.unlink(missing_ok=True)
            try:
                workdir.rmdir()
            except OSError:
                pass


# -- helpers -------------------------------------------------------------
def _entry_from_dict(e: Any) -> QuarantineEntry | None:
    """Build a QuarantineEntry, tolerating malformed/partial index entries."""
    if not isinstance(e, dict) or "id" not in e:
        return None
    kw = {k: v for k, v in e.items() if k in QuarantineEntry.__dataclass_fields__}
    try:
        entry = QuarantineEntry(**kw)
    except TypeError:
        return None
    # Coerce the fields that get displayed/compared so a hand-edited or damaged
    # index can't put a non-string where code (and the UI) expects text.
    entry.id = str(entry.id)
    entry.original_path = _clean_text(entry.original_path, 4096)
    entry.quarantined_at = _clean_text(entry.quarantined_at, 64)
    entry.verdict = _clean_text(entry.verdict, 32)
    entry.size = entry.size if isinstance(entry.size, int) and not isinstance(entry.size, bool) else 0
    entry.sha256 = entry.sha256 if isinstance(entry.sha256, str) else None
    entry.findings = [f for f in entry.findings if isinstance(f, dict)] if isinstance(entry.findings, list) else []
    entry.restored, entry.encrypted, entry.imported = (
        entry.restored is True, entry.encrypted is True, entry.imported is True)
    entry.restored_at = entry.restored_at if isinstance(entry.restored_at, str) else None
    entry.last_rescan = entry.last_rescan if isinstance(entry.last_rescan, dict) else None
    return entry


def _clean_text(value: Any, limit: int) -> str:
    return "".join(c for c in str(value or "") if c.isprintable())[:limit]


def _timestamp(iso: Any) -> float | None:
    try:
        dt = datetime.fromisoformat(str(iso))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def parse_age(text: str) -> float:
    """'30d', '12h', '2w' or a bare number of days -> days (float)."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([hdw]?)\s*", str(text).lower())
    if not m:
        raise ValueError(f"not a valid age: {text!r} (use e.g. 30d, 12h, 2w)")
    value = float(m.group(1))
    return value * {"h": 1 / 24, "d": 1.0, "w": 7.0, "": 1.0}[m.group(2)]


def _publish(tmp: Path, dst: Path, *, clobber: bool) -> None:
    """Move a finished temp file into place. Without ``clobber`` this fails
    (FileExistsError) rather than replace a file that appeared in the meantime."""
    if clobber:
        os.replace(tmp, dst)
    elif os.name == "nt":
        os.rename(tmp, dst)             # Windows rename never overwrites
    else:
        try:
            os.link(tmp, dst)           # link() fails if dst exists; atomic no-clobber
        except FileExistsError:
            raise
        except OSError:
            # Filesystem without hard links (FAT, some network mounts): fall
            # back to check-then-rename.
            if os.path.lexists(dst):
                raise FileExistsError(str(dst)) from None
            os.replace(tmp, dst)
        else:
            os.unlink(tmp)
    fsync_dir(dst.parent)


def _write_verified(chunks: Iterable[bytes], dst: Path, expected_sha: str | None,
                    *, clobber: bool) -> None:
    """Write a stream to ``dst`` atomically, but only if it hashes to
    ``expected_sha``. Nothing appears at ``dst`` on a mismatch."""
    digest = hashlib.sha256()
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=".qtmp-")
    try:
        with os.fdopen(fd, "wb") as fout:
            for chunk in chunks:
                digest.update(chunk)
                fout.write(chunk)
            fout.flush()
            os.fsync(fout.fileno())
        if expected_sha and digest.hexdigest() != expected_sha:
            raise QuarantineError("stored data does not match its recorded hash "
                                  "(damaged or altered); not restoring")
        _publish(Path(tmp), dst, clobber=clobber)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


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
            for chunk in iter(lambda: fin.read(_CHUNK), b""):
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


# -- authenticated encryption -------------------------------------------
# A sealed file is a sequence of AES-256-GCM chunks (the "STREAM" construction):
# each chunk's nonce is an 11-byte counter plus a final-chunk flag, so chunks
# cannot be reordered, dropped, duplicated or truncated without detection.
def _need_crypto() -> None:
    if not _CRYPTO:
        raise QuarantineError("the 'cryptography' package is required for quarantine encryption"
                              + (f" (it failed to load: {_CRYPTO_ERROR})" if _CRYPTO_ERROR else ""))


def _master_key(*, create: bool) -> bytes:
    """This machine's quarantine key (from the OS secret store)."""
    _need_crypto()
    from . import secrets as _secrets
    stored = _secrets.load_secret(_KEY_NAME)
    if stored:
        try:
            raw = base64.b64decode(stored, validate=True)
            if len(raw) == 32:
                return raw
        except ValueError:
            pass
        raise QuarantineError("the quarantine encryption key in the secret store is damaged")
    if not create:
        raise QuarantineError("the quarantine encryption key is missing from the secret store; "
                              "encrypted items cannot be opened on this machine")
    raw = _stdlib_secrets.token_bytes(32)
    _secrets.store_secret(_KEY_NAME, base64.b64encode(raw).decode("ascii"))
    if _secrets.load_secret(_KEY_NAME) is None:
        # Never seal data under a key we failed to keep.
        raise QuarantineError("could not save the quarantine encryption key to the secret store")
    return raw


def _file_key(master: bytes, path: Path, entry_id: str) -> bytes:
    with open(path, "rb") as fh:
        header = fh.read(20)
    if len(header) != 20 or header[:4] != _ENC_MAGIC:
        raise QuarantineError(f"quarantined data for {entry_id} is not a valid sealed file")
    return _derive(master, header[4:], entry_id)


def _derive(master: bytes, salt: bytes, entry_id: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"warden-quarantine-v1|" + entry_id.encode()).derive(master)


def _nonce(counter: int, final: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


def _seal_stream(chunks: Iterable[bytes], out: Any, key: bytes, aad: bytes) -> None:
    """Encrypt a stream of plaintext chunks to ``out`` (a binary file object)."""
    aes = AESGCM(key)
    counter = 0
    pending: bytes | None = None
    for chunk in _rechunk(chunks):
        if pending is not None:
            out.write(aes.encrypt(_nonce(counter, False), pending, aad))
            counter += 1
        pending = chunk
    out.write(aes.encrypt(_nonce(counter, True), pending or b"", aad))


def _rechunk(chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Regroup an arbitrary byte stream into exact ``_CHUNK``-sized pieces."""
    buf = bytearray()
    for chunk in chunks:
        buf += chunk
        while len(buf) >= _CHUNK:
            yield bytes(buf[:_CHUNK])
            del buf[:_CHUNK]
    if buf:
        yield bytes(buf)


def _open_stream(fh: Any, key: bytes, aad: bytes, what: str) -> Iterator[bytes]:
    """Decrypt chunks from ``fh`` (positioned after the header)."""
    aes = AESGCM(key)
    counter = 0
    current = fh.read(_CHUNK + _TAG)
    while True:
        nxt = fh.read(_CHUNK + _TAG)
        final = not nxt
        try:
            yield aes.decrypt(_nonce(counter, final), current, aad)
        except InvalidTag:
            raise QuarantineError(f"{what} failed its integrity check "
                                  f"(wrong key/password, or the data was altered)") from None
        if final:
            return
        current, counter = nxt, counter + 1


def _open_sealed(path: Path, key: bytes, aad: bytes) -> Iterator[bytes]:
    with open(path, "rb") as fh:
        fh.seek(20)
        yield from _open_stream(fh, key, aad, "quarantined data")


def _seal_copy_atomic(src: Path, dst: Path, master: bytes, entry_id: str, *,
                      mode: int | None = None) -> str:
    """Encrypt src -> dst atomically; returns the SHA-256 of the plaintext
    read (same single-read guarantee as ``_xor_copy_atomic``)."""
    _need_crypto()
    dst = Path(dst)
    salt = _stdlib_secrets.token_bytes(16)
    key = _derive(master, salt, entry_id)
    digest = hashlib.sha256()

    def reader(fin: Any) -> Iterator[bytes]:
        for chunk in iter(lambda: fin.read(_CHUNK), b""):
            digest.update(chunk)
            yield chunk

    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=".qtmp-")
    try:
        with os.fdopen(fd, "wb") as fout, open(src, "rb") as fin:
            fout.write(_ENC_MAGIC + salt)
            _seal_stream(reader(fin), fout, key, entry_id.encode())
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


def _password_key(password: str, salt: bytes) -> bytes:
    _need_crypto()
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode("utf-8"))


def _password_seal(src: Path, dst: Path, password: str) -> None:
    salt = _stdlib_secrets.token_bytes(16)
    key = _password_key(password, salt)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(_BUNDLE_MAGIC + salt)
        _seal_stream(iter(lambda: fin.read(_CHUNK), b""), fout, key, b"warden-quarantine-bundle-v1")
        fout.flush()
        os.fsync(fout.fileno())


def _password_open(src: Path, dst: Path, password: str) -> None:
    with open(src, "rb") as fin:
        header = fin.read(20)
        if len(header) != 20 or header[:4] != _BUNDLE_MAGIC:
            raise QuarantineError("not a password-protected Warden bundle")
        key = _password_key(password, header[4:])
        with open(dst, "wb") as fout:
            for chunk in _open_stream(fin, key, b"warden-quarantine-bundle-v1", "bundle"):
                fout.write(chunk)
