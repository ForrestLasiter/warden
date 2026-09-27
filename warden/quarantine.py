"""Quarantine: isolate suspicious files safely and reversibly.

Design goals:
  * Never permanently delete on the user's behalf (that's a Prohibited action).
  * The stored copy must not be runnable, so a quarantined executable can't be
    launched by accident. We XOR every byte with a fixed key - trivial to
    reverse on restore, but the blob is no longer a valid PE/script.
  * Every action is recorded so it can be undone.

Layout under ~/.warden/quarantine/:
    index.json                  -> list of entries
    <id>.qbin                   -> neutralized file bytes
    <id>.json                   -> per-entry metadata (also in index)
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

from .config import Config
from .models import FileResult, now_iso

# Fixed XOR key used to neutralize stored bytes. Not secret - its only job is to
# ensure the quarantined copy isn't directly executable.
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


class Quarantine:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.config.ensure_dirs()
        self.dir = self.config.quarantine_dir
        self.index_path = self.dir / "index.json"

    # -- index io ---------------------------------------------------------
    def _load_index(self) -> list[dict[str, Any]]:
        if not self.index_path.exists():
            return []
        try:
            return json.loads(self.index_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def _save_index(self, entries: list[dict[str, Any]]) -> None:
        self.index_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    def list_entries(self) -> list[QuarantineEntry]:
        return [QuarantineEntry(**e) for e in self._load_index()]

    # -- actions ----------------------------------------------------------
    def quarantine_file(self, result: FileResult) -> QuarantineEntry:
        """Move a flagged file into quarantine, neutralized. Removes the original."""
        src = Path(result.path)
        entry_id = uuid.uuid4().hex[:16]
        blob_path = self.dir / f"{entry_id}.qbin"

        # Copy+neutralize into quarantine first, then remove the original, so a
        # failure never loses the file.
        _xor_copy(src, blob_path)

        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(src.resolve()),
            quarantined_at=now_iso(),
            size=result.size,
            sha256=result.sha256,
            verdict=result.verdict.label,
            findings=[f.to_dict() for f in result.findings],
        )

        # Remove the live copy now that a neutralized backup exists.
        try:
            os.remove(src)
        except OSError as exc:
            # Roll back: we couldn't remove the original, so drop the blob and
            # surface the problem rather than leaving a half-done state.
            blob_path.unlink(missing_ok=True)
            raise QuarantineError(f"could not remove original {src}: {exc}") from exc

        index = self._load_index()
        index.append(entry.to_dict())
        self._save_index(index)
        (self.dir / f"{entry_id}.json").write_text(
            json.dumps(entry.to_dict(), indent=2), encoding="utf-8"
        )
        return entry

    def restore(self, entry_id: str, dest: Path | None = None) -> Path:
        """Restore a quarantined file to its original location (or ``dest``)."""
        index = self._load_index()
        match = next((e for e in index if e["id"] == entry_id), None)
        if match is None:
            raise QuarantineError(f"no quarantine entry with id {entry_id}")
        blob_path = self.dir / f"{entry_id}.qbin"
        if not blob_path.exists():
            raise QuarantineError(f"quarantined data missing for {entry_id}")

        target = dest or Path(match["original_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        _xor_copy(blob_path, target)

        match["restored"] = True
        match["restored_at"] = now_iso()
        self._save_index(index)
        return target

    def delete(self, entry_id: str) -> None:
        """Permanently remove a quarantined blob. Caller must confirm intent."""
        index = self._load_index()
        remaining = [e for e in index if e["id"] != entry_id]
        if len(remaining) == len(index):
            raise QuarantineError(f"no quarantine entry with id {entry_id}")
        (self.dir / f"{entry_id}.qbin").unlink(missing_ok=True)
        (self.dir / f"{entry_id}.json").unlink(missing_ok=True)
        self._save_index(remaining)


class QuarantineError(Exception):
    pass


def _xor_copy(src: Path, dst: Path, key: int = _XOR_KEY) -> None:
    """Stream-copy src -> dst, XOR-ing every byte with key (self-inverse)."""
    tbl = bytes(b ^ key for b in range(256))
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for chunk in iter(lambda: fin.read(1024 * 1024), b""):
            fout.write(chunk.translate(tbl))
