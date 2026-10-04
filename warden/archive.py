"""Bounded, in-memory archive reading.

Malware usually arrives *inside* something: a zip attached to an email, a
tarball, a gzip'd script. This module opens the common container formats with
the standard library and hands each member's bytes back to the scanner, so the
normal engines run on the contents and not just the wrapper.

Safety properties (this code handles hostile input by definition):

  * Nothing is ever extracted to disk - members are read into memory only, so
    path traversal ("zip slip"), symlink members and device nodes are moot.
  * Declared sizes are never trusted. Every read is capped, and a running total
    of real decompressed bytes enforces the limits, which is what defeats
    decompression bombs (including ones with forged headers).
  * Member count, per-member size, total size, compression ratio and nesting
    depth are all bounded. Hitting a bound stops the walk and is *reported*,
    never silently ignored.

Supported: zip (and zip-based formats: jar, docx, apk, ...), tar, tar.gz /
tar.bz2 / tar.xz, and single-stream gzip / bzip2 / xz. Not supported: 7z, rar
and password-protected members (install ClamAV for the former; the latter are
reported as uninspectable).
"""

from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field

MiB = 1024 * 1024


@dataclass(slots=True)
class ArchiveLimits:
    max_members: int = 2000            # members inspected per archive
    max_member_bytes: int = 64 * MiB   # largest single member read
    max_total_bytes: int = 256 * MiB   # decompressed bytes per top-level file
    max_ratio: int = 200               # decompressed : compressed
    max_depth: int = 3                 # archive-in-archive nesting


@dataclass(slots=True)
class ArchiveStats:
    """What happened while walking one top-level archive (all nesting levels)."""
    members_scanned: int = 0
    members_skipped: int = 0
    encrypted: int = 0
    total_bytes: int = 0
    bomb: bool = False
    truncated: bool = False            # a limit stopped the walk early
    reasons: list[str] = field(default_factory=list)

    def note(self, reason: str) -> None:
        if reason not in self.reasons and len(self.reasons) < 20:
            self.reasons.append(reason)


def archive_kind(data: bytes) -> str | None:
    """Identify a supported container by magic bytes (never by extension)."""
    head = data[:8]
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh" and len(data) > 3 and data[3:4] in b"123456789":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(data) >= 263 and data[257:262] == b"ustar":
        return "tar"
    return None


def iter_members(data: bytes, name: str, limits: ArchiveLimits,
                 stats: ArchiveStats) -> Iterator[tuple[str, bytes]]:
    """Yield ``(member_name, bytes)`` for one archive level. Never raises.

    ``stats`` is shared across nesting levels so the totals bound the whole
    top-level file, not each layer separately.
    """
    kind = archive_kind(data)
    try:
        if kind == "zip":
            yield from _zip_members(data, limits, stats)
        elif kind == "tar":
            yield from _tar_members(data, limits, stats)
        elif kind in ("gzip", "bzip2", "xz"):
            yield from _stream_members(data, kind, name, limits, stats)
    except Exception as exc:  # noqa: BLE001 - corrupt/hostile container
        stats.truncated = True
        stats.note(f"archive could not be fully read ({type(exc).__name__})")


def _account(stats: ArchiveStats, limits: ArchiveLimits, n: int, compressed: int) -> bool:
    """Charge ``n`` decompressed bytes. False once the archive is over budget."""
    stats.total_bytes += n
    if n > MiB and n > max(compressed, 1) * limits.max_ratio:
        stats.bomb = True
        stats.truncated = True
        stats.note(f"compression ratio above {limits.max_ratio}:1 (possible decompression bomb)")
        return False
    if stats.total_bytes > limits.max_total_bytes:
        stats.truncated = True
        stats.note(f"decompressed size limit reached ({limits.max_total_bytes // MiB} MiB)")
        return False
    return True


def _zip_members(data: bytes, limits: ArchiveLimits, stats: ArchiveStats) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        for seen, info in enumerate(infos):
            if seen >= limits.max_members:
                stats.members_skipped += len(infos) - seen
                stats.truncated = True
                stats.note(f"member limit reached ({limits.max_members})")
                return
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                stats.encrypted += 1
                stats.members_skipped += 1
                continue
            try:
                with zf.open(info) as fh:
                    blob = fh.read(limits.max_member_bytes + 1)
            except Exception as exc:  # noqa: BLE001 - bad CRC, unsupported method, ...
                stats.members_skipped += 1
                stats.note(f"unreadable member ({type(exc).__name__})")
                continue
            if len(blob) > limits.max_member_bytes:
                stats.members_skipped += 1
                stats.note(f"member larger than {limits.max_member_bytes // MiB} MiB skipped")
                # Still charge it, so a bomb made of huge members stops the walk.
                if not _account(stats, limits, len(blob), info.compress_size):
                    return
                continue
            if not _account(stats, limits, len(blob), info.compress_size):
                return
            yield info.filename, blob


def _tar_members(data: bytes, limits: ArchiveLimits, stats: ArchiveStats) -> Iterator[tuple[str, bytes]]:
    # mode "r:" = plain tar only: compression is peeled (and bounded) separately
    # by _stream_members, so tarfile never inflates anything on its own.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        seen = 0
        for ti in tf:
            if seen >= limits.max_members:
                stats.truncated = True
                stats.note(f"member limit reached ({limits.max_members})")
                return
            seen += 1
            if not ti.isreg():
                continue        # dirs, links, devices: nothing to scan, never followed
            if ti.size > limits.max_member_bytes:
                stats.members_skipped += 1
                stats.note(f"member larger than {limits.max_member_bytes // MiB} MiB skipped")
                continue
            fh = tf.extractfile(ti)
            if fh is None:
                continue
            blob = fh.read(limits.max_member_bytes + 1)
            # A plain tar can't expand, so charge it against the total only.
            if not _account(stats, limits, len(blob), len(blob)):
                return
            yield ti.name, blob


def _stream_members(data: bytes, kind: str, name: str, limits: ArchiveLimits,
                    stats: ArchiveStats) -> Iterator[tuple[str, bytes]]:
    cap = min(limits.max_total_bytes - stats.total_bytes, limits.max_total_bytes)
    if cap <= 0:
        stats.truncated = True
        stats.note(f"decompressed size limit reached ({limits.max_total_bytes // MiB} MiB)")
        return
    blob, complete = _bounded_decompress(data, kind, cap)
    if not complete:
        stats.truncated = True
        stats.members_skipped += 1
        ratio_hit = len(blob) > max(len(data), 1) * limits.max_ratio
        if ratio_hit:
            stats.bomb = True
            stats.note(f"compression ratio above {limits.max_ratio}:1 (possible decompression bomb)")
        else:
            stats.note(f"decompressed size limit reached ({limits.max_total_bytes // MiB} MiB)")
        return
    if not _account(stats, limits, len(blob), len(data)):
        return
    inner = _strip_suffix(name, kind)
    if archive_kind(blob) == "tar":
        # tar.gz & friends: walk the tar directly rather than as a nested level.
        yield from _tar_members(blob, limits, stats)
    elif len(blob) > limits.max_member_bytes:
        stats.members_skipped += 1
        stats.note(f"member larger than {limits.max_member_bytes // MiB} MiB skipped")
    else:
        yield inner, blob


def _bounded_decompress(data: bytes, kind: str, cap: int) -> tuple[bytes, bool]:
    """Inflate at most ``cap`` bytes. Returns (bytes, finished_within_cap)."""
    out = bytearray()
    buf = data
    step = 4 * MiB
    # gzip and bzip2 files may be several streams concatenated; loop over them.
    for _ in range(4096):
        dec = _decompressor(kind)
        chunk = buf
        while True:
            room = cap + 1 - len(out)
            if room <= 0:
                return bytes(out[:cap]), False
            piece = dec.decompress(chunk, min(room, step))
            out += piece
            chunk = b""
            if dec.eof:
                break
            if not piece and getattr(dec, "needs_input", True):
                # Truncated stream: keep what we got and call it finished.
                return bytes(out), True
        buf = dec.unused_data.lstrip(b"\x00")
        if not buf or archive_kind(buf) != kind:
            break
    return bytes(out), len(out) <= cap


class _ZlibAdapter:
    """Give zlib's decompressobj the same surface as bz2/lzma decompressors."""

    def __init__(self) -> None:
        self._d = zlib.decompressobj(wbits=31)
        self._pending = b""

    def decompress(self, data: bytes, max_length: int) -> bytes:
        src = self._pending + data
        out = self._d.decompress(src, max_length)
        self._pending = self._d.unconsumed_tail
        return out

    @property
    def eof(self) -> bool:
        return self._d.eof

    @property
    def needs_input(self) -> bool:
        return not self._pending and not self._d.eof

    @property
    def unused_data(self) -> bytes:
        return self._d.unused_data


def _decompressor(kind: str):
    if kind == "gzip":
        return _ZlibAdapter()
    if kind == "bzip2":
        return bz2.BZ2Decompressor()
    return lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)


def _strip_suffix(name: str, kind: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1] or "stream"
    low = base.lower()
    for suffix, repl in ((".tgz", ".tar"), (".tbz2", ".tar"), (".txz", ".tar"),
                         (".gz", ""), (".bz2", ""), (".xz", "")):
        if low.endswith(suffix):
            return base[:-len(suffix)] + repl or "stream"
    return base + ".out"
