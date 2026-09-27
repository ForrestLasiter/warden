"""Engine framework.

An engine inspects one file and returns zero or more ``Finding`` objects.
Engines share a ``ScanContext`` so we read each file's bytes and compute its
hash only once, no matter how many engines run.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..models import Finding


class ScanContext:
    """Per-file state passed to every engine.

    Reads file bytes lazily and caches them, so multiple content engines
    (YARA, heuristics) share a single read. ``max_read`` caps how much we
    pull into memory for very large files.
    """

    __slots__ = ("path", "size", "max_read", "_data", "_sha256", "_read_error")

    def __init__(self, path: Path, size: int, max_read: int):
        self.path = path
        self.size = size
        self.max_read = max_read
        self._data: bytes | None = None
        self._sha256: str | None = None
        self._read_error: str | None = None

    @property
    def read_error(self) -> str | None:
        return self._read_error

    def data(self) -> bytes:
        """File contents, capped at ``max_read`` bytes. Cached. Never raises."""
        if self._data is None:
            try:
                with open(self.path, "rb") as fh:
                    self._data = fh.read(self.max_read)
            except OSError as exc:
                self._read_error = str(exc)
                self._data = b""
        return self._data

    def sha256(self) -> str | None:
        """Full-file SHA-256 (streamed, not capped). Cached. None on error."""
        if self._sha256 is None and self._read_error is None:
            h = hashlib.sha256()
            try:
                with open(self.path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
                self._sha256 = h.hexdigest()
            except OSError as exc:
                self._read_error = str(exc)
        return self._sha256


@runtime_checkable
class Engine(Protocol):
    name: str

    def available(self) -> bool:
        """Whether this engine can run (rules loaded, binary present, etc.)."""
        ...

    def scan(self, ctx: ScanContext) -> list[Finding]:
        ...
