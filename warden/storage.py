"""Atomic, durable on-disk writes for Warden's small state files.

All of Warden's persistent state (config, quarantine index + sidecars, history,
schedules, reputation cache) is written through here so that a crash, a power
loss, or two processes writing at once can never leave a half-written or
truncated file. The pattern is the standard one: write a temp file in the same
directory, flush + fsync it, then ``os.replace`` (atomic on POSIX and Windows).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

_IS_WINDOWS = os.name == "nt"


def fsync_dir(path: Path) -> None:
    """Best-effort fsync of a directory so a rename is durable (POSIX only)."""
    if _IS_WINDOWS:
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_write_bytes(path: str | os.PathLike, data: bytes, *, mode: int | None = None) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".wtmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None and not _IS_WINDOWS:
            os.chmod(tmp, mode)
        os.replace(tmp, path)          # atomic swap
        fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path: str | os.PathLike, text: str, *, encoding: str = "utf-8",
                      mode: int | None = None) -> None:
    atomic_write_bytes(path, text.encode(encoding), mode=mode)


def atomic_write_json(path: str | os.PathLike, obj: Any, *, indent: int | None = 2,
                      mode: int | None = None) -> None:
    atomic_write_text(path, json.dumps(obj, indent=indent), mode=mode)


def secure_dir(path: str | os.PathLike, *, mode: int = 0o700) -> Path:
    """Create a directory that only the owner can access (POSIX; best-effort)."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if not _IS_WINDOWS:
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    return path
