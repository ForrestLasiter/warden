"""Synthetic file builders for tests.

Everything here is assembled in memory from harmless bytes - there are no real
samples in this repository. The builders produce *structurally* valid
containers (OLE compound files, VBA compressed streams, ELF/Mach-O headers,
archives) so the parsers can be exercised end to end.
"""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile

ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF


def vba_compress(source: bytes) -> bytes:
    """MS-OVBA compressed container using literal tokens only (valid, just not
    space-efficient) - enough to round-trip through a real decompressor."""
    out = bytearray(b"\x01")
    # 3640 literals + their flag bytes is the most that fits one 4098-byte chunk.
    for i in range(0, len(source), 3640):
        chunk = source[i:i + 3640]
        body = bytearray()
        for j in range(0, len(chunk), 8):
            body.append(0x00)                 # flag byte: eight literals follow
            body += chunk[j:j + 8]
        header = 0xB000 | (len(body) + 2 - 3)   # compressed, signature 0b011
        out += struct.pack("<H", header) + body
    return bytes(out)


def make_ole(streams: dict[str, bytes]) -> bytes:
    """A minimal version-3 OLE compound file holding ``streams``.

    Streams under 4096 bytes go into the mini stream (as real writers do);
    larger ones get regular sector chains.
    """
    ssize = 512
    sectors: list[bytes] = [b""]          # sector 0 is reserved for the FAT
    fat: list[int] = [FATSECT]

    def add_chain(data: bytes) -> int:
        if not data:
            return ENDOFCHAIN
        start = len(sectors)
        chunks = [data[i:i + ssize].ljust(ssize, b"\x00") for i in range(0, len(data), ssize)]
        for k, chunk in enumerate(chunks):
            sectors.append(chunk)
            fat.append(start + k + 1 if k < len(chunks) - 1 else ENDOFCHAIN)
        return start

    mini = bytearray()
    minifat: list[int] = []
    entries: list[tuple[str, int, int, int]] = []     # name, type, start, size
    for name, data in streams.items():
        if len(data) < 4096:
            first = len(minifat)
            count = max(1, -(-len(data) // 64))
            for k in range(count):
                minifat.append(first + k + 1 if k < count - 1 else ENDOFCHAIN)
            mini += data.ljust(count * 64, b"\x00")
            entries.append((name, 2, first, len(data)))
        else:
            entries.append((name, 2, add_chain(data), len(data)))

    mini_start = add_chain(bytes(mini))
    minifat_raw = b"".join(struct.pack("<I", v) for v in minifat)
    minifat_start = add_chain(minifat_raw.ljust(-(-max(len(minifat_raw), 1) // ssize) * ssize, b"\xff"))
    minifat_sectors = -(-max(len(minifat_raw), 1) // ssize)

    def dirent(name: str, etype: int, start: int, size: int, child: int = NOSTREAM,
               right: int = NOSTREAM) -> bytes:
        raw = name.encode("utf-16-le") + b"\x00\x00"
        ent = bytearray(128)
        ent[:len(raw)] = raw
        struct.pack_into("<H", ent, 64, len(raw))
        ent[66] = etype
        ent[67] = 1
        struct.pack_into("<III", ent, 68, NOSTREAM, right, child)
        struct.pack_into("<I", ent, 116, start)
        struct.pack_into("<Q", ent, 120, size)
        return bytes(ent)

    directory = dirent("Root Entry", 5, mini_start, len(mini), child=1 if entries else NOSTREAM)
    for idx, (name, etype, start, size) in enumerate(entries):
        right = idx + 2 if idx < len(entries) - 1 else NOSTREAM
        directory += dirent(name, etype, start, size, right=right)
    directory = directory.ljust(-(-len(directory) // ssize) * ssize, b"\x00")
    dir_start = add_chain(directory)

    assert len(fat) <= ssize // 4, "test OLE too large for a single FAT sector"
    sectors[0] = b"".join(struct.pack("<I", v) for v in fat).ljust(ssize, b"\xff")

    header = bytearray(512)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 40, 0, 1, dir_start, 0, 4096,
                     minifat_start, minifat_sectors, ENDOFCHAIN, 0)
    struct.pack_into("<109I", header, 76, 0, *([FREESECT] * 108))
    return bytes(header) + b"".join(sectors)


def make_vba_project(source: str) -> bytes:
    """An OLE file shaped like a vbaProject.bin with one module."""
    module = b"\x00" * 24 + vba_compress(source.encode("latin-1"))   # p-code stub, then source
    return make_ole({
        "_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00",
        "dir": vba_compress(b"\x01\x00\x04\x00\x00\x00"),
        "ThisDocument": module,
    })


def make_zip(members: dict[str, bytes], *, compress: bool = True) -> bytes:
    buf = io.BytesIO()
    method = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_ooxml(members: dict[str, bytes]) -> bytes:
    base = {"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"}
    base.update(members)
    return make_zip(base)


def mark_zip_encrypted(data: bytes) -> bytes:
    """Flip the 'encrypted' flag on every entry of a zip (local + central)."""
    out = bytearray(data)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = out.find(sig)
        while pos != -1:
            out[pos + off] |= 0x01
            pos = out.find(sig, pos + 4)
    return bytes(out)


def make_tar(members: dict[str, bytes], mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def make_elf64(*, rwx: bool = False, sections: bool = True, upx: bool = False) -> bytes:
    """A tiny little-endian x86-64 ELF header + one PT_LOAD + PT_INTERP."""
    interp = b"/lib64/ld-linux-x86-64.so.2\x00"
    phoff, phentsize, phnum = 64, 56, 2
    interp_off = phoff + phentsize * phnum
    flags = 7 if rwx else 5
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    shoff = 4096 if sections else 0
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, phoff, shoff, 0, 64, phentsize, phnum,
        64, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, flags, 0, 0x400000, 0x400000, 0x200, 0x200, 0x1000)
    pinterp = struct.pack("<IIQQQQQQ", 3, 4, interp_off, 0, 0, len(interp), len(interp), 1)
    body = header + load + pinterp + interp
    if upx:
        body += b"UPX!"
    return body.ljust(512, b"\x00")


def make_macho64(*, cputype: int = 0x0100000C, signed: bool = False, rwx: bool = False) -> bytes:
    """A little-endian 64-bit Mach-O with one segment (+ optional signature)."""
    seg = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0, 0x1000, 0, 0x1000,
                      7, 7 if rwx else 5, 0, 0)
    cmds = [seg]
    if signed:
        cmds.append(struct.pack("<IIII", 0x1D, 16, 0x2000, 0x100))
    blob = b"".join(cmds)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, 0, 2, len(cmds), len(blob), 0, 0)
    return header + blob
