"""Executable-format metadata: PE, ELF and Mach-O.

Pure-Python, bounds-checked header parsing. Nothing here executes or loads the
file - it only reads fixed-size structures out of the bytes the scanner already
holds, so a malformed or hostile binary can at worst produce ``None``.

``binary_info`` returns a small JSON-safe dict describing the file (format,
architecture, type, sections/segments, whether a signature is embedded) and a
list of structural *observations* the heuristics engine turns into findings.
"""

from __future__ import annotations

import struct
from typing import Any

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None  # type: ignore

# Bounds so a crafted header can't make us loop for a long time.
_MAX_HEADERS = 256          # program/section headers, load commands
_MAX_PE_BYTES = 64 * 1024 * 1024

# Known packer section names -> a hint that the binary is packed/obfuscated.
PACKER_SECTIONS = {
    b"UPX0", b"UPX1", b"UPX2", b".aspack", b".adata", b"ASPack", b".nsp0",
    b".nsp1", b"FSG!", b".petite", b"pebundle", b"MPRESS1", b"MPRESS2",
    b".themida", b".vmp0", b".vmp1", b".enigma1",
}

RISKY_IMPORTS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "URLDownloadToFile", "WinExec", "ShellExecuteA",
    "CreateProcessA", "InternetOpenA", "InternetReadFile", "CryptEncrypt",
    "RegSetValueExA", "GetProcAddress", "LoadLibraryA", "IsDebuggerPresent",
}

_PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0x1C4: "armv7",
                0xAA64: "arm64", 0x200: "ia64"}
_ELF_MACHINES = {3: "x86", 62: "x86_64", 40: "arm", 183: "arm64", 8: "mips",
                 20: "ppc", 21: "ppc64", 243: "riscv", 22: "s390", 2: "sparc"}
_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}
_MACHO_CPUS = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64",
               18: "ppc", 0x01000012: "ppc64"}
_MACHO_TYPES = {1: "object", 2: "executable", 4: "core", 5: "preload", 6: "dylib",
                7: "dylinker", 8: "bundle", 9: "dylib-stub", 10: "dsym", 11: "kext"}

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": (">", False), b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xcf": (">", True), b"\xcf\xfa\xed\xfe": ("<", True),
}
_FAT_MAGICS = (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")


def identify(data: bytes) -> str | None:
    """Return 'pe', 'elf', 'macho' or None from the leading magic bytes."""
    head = data[:8]
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in _MACHO_MAGICS:
        return "macho"
    if head[:4] in _FAT_MAGICS and len(data) >= 8:
        # Java .class files share 0xCAFEBABE; there bytes 4..8 are a version
        # (>= 45), whereas a fat Mach-O holds a small architecture count.
        if 0 < struct.unpack(">I", data[4:8])[0] <= 20:
            return "macho"
    return None


def binary_info(data: bytes, size: int | None = None) -> dict[str, Any] | None:
    """Metadata for an executable, or None if ``data`` isn't one (or is too
    malformed to describe). Never raises."""
    kind = identify(data)
    try:
        if kind == "pe":
            return _pe_info(data, size if size is not None else len(data))
        if kind == "elf":
            return _elf_info(data)
        if kind == "macho":
            return _macho_info(data)
    except Exception:  # noqa: BLE001 - hostile input must never break a scan
        return {"format": kind, "malformed": True, "observations": []}
    return None


# -- PE ------------------------------------------------------------------
def _pe_info(data: bytes, size: int) -> dict[str, Any] | None:
    if pefile is None or size > _MAX_PE_BYTES:
        return {"format": "pe", "observations": [], "parsed": False}
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:  # noqa: BLE001 - "MZ" but not a valid PE
        return None
    obs: list[dict[str, Any]] = []
    try:
        fh = pe.FILE_HEADER
        characteristics = getattr(fh, "Characteristics", 0)
        opt = getattr(pe, "OPTIONAL_HEADER", None)
        info: dict[str, Any] = {
            "format": "pe",
            "arch": _PE_MACHINES.get(getattr(fh, "Machine", 0), hex(getattr(fh, "Machine", 0))),
            "type": "dll" if characteristics & 0x2000 else "executable",
            "timestamp": int(getattr(fh, "TimeDateStamp", 0) or 0),
            "subsystem": int(getattr(opt, "Subsystem", 0) or 0) if opt else 0,
            "sections": [],
            "signature_embedded": False,
            "dotnet": False,
        }
        packer = None
        for section in pe.sections[:_MAX_HEADERS]:
            raw = section.Name.rstrip(b"\x00")
            name = raw.decode(errors="replace")
            flags = int(getattr(section, "Characteristics", 0) or 0)
            wx = bool(flags & 0x80000000) and bool(flags & 0x20000000)
            info["sections"].append({
                "name": name,
                "raw_size": int(section.SizeOfRawData),
                "virtual_size": int(section.Misc_VirtualSize),
                "entropy": round(float(section.get_entropy()), 2),
                "writable_executable": wx,
            })
            if packer is None and (raw in PACKER_SECTIONS or raw.upper().startswith(b"UPX")):
                packer = name
        if packer:
            obs.append({"id": "packer-section", "section": packer})
        wx_sections = [s["name"] for s in info["sections"] if s["writable_executable"]]
        if wx_sections:
            obs.append({"id": "pe-writable-executable-section", "sections": wx_sections[:6]})

        if opt is not None:
            dirs = getattr(opt, "DATA_DIRECTORY", []) or []
            # 4 = security (Authenticode blob), 14 = CLR header (.NET)
            if len(dirs) > 4 and int(getattr(dirs[4], "Size", 0) or 0):
                info["signature_embedded"] = True
            if len(dirs) > 14 and int(getattr(dirs[14], "Size", 0) or 0):
                info["dotnet"] = True

        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            risky: set[str] = set()
            libs: list[str] = []
            for entry in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])[:_MAX_HEADERS]:
                if entry.dll:
                    libs.append(entry.dll.decode(errors="replace"))
                for imp in entry.imports:
                    if imp.name:
                        nm = imp.name.decode(errors="replace")
                        if nm in RISKY_IMPORTS:
                            risky.add(nm)
            info["imported_libraries"] = libs[:64]
            try:
                info["imphash"] = pe.get_imphash() or None
            except Exception:  # noqa: BLE001
                info["imphash"] = None
            if risky:
                obs.append({"id": "risky-imports", "imports": sorted(risky)})
        except Exception:  # noqa: BLE001
            pass
        info["observations"] = obs
        return info
    finally:
        pe.close()


# -- ELF -----------------------------------------------------------------
def _elf_info(data: bytes) -> dict[str, Any] | None:
    if len(data) < 52:
        return None
    is64 = data[4] == 2
    end = "<" if data[5] != 2 else ">"
    if is64:
        if len(data) < 64:
            return None
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            end + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            end + "HHIIIIIHHHHHH", data, 16)

    info: dict[str, Any] = {
        "format": "elf",
        "bits": 64 if is64 else 32,
        "endian": "little" if end == "<" else "big",
        "arch": _ELF_MACHINES.get(e_machine, str(e_machine)),
        "type": _ELF_TYPES.get(e_type, str(e_type)),
        "entry": e_entry,
        "interpreter": None,
        "dynamic": False,
        "stripped": True,
        "sections": [],
        "signature_embedded": False,
    }
    obs: list[dict[str, Any]] = []

    # Program headers: interpreter, dynamic linking, RWX segments.
    rwx = False
    for i in range(min(e_phnum, _MAX_HEADERS)):
        off = e_phoff + i * e_phentsize
        if is64:
            if off + 56 > len(data):
                break
            p_type, p_flags, p_offset, _va, _pa, p_filesz = struct.unpack_from(end + "IIQQQQ", data, off)
        else:
            if off + 32 > len(data):
                break
            p_type, p_offset, _va, _pa, p_filesz, _memsz, p_flags = struct.unpack_from(end + "IIIIIII", data, off)
        if p_type == 3 and 0 < p_filesz <= 4096 and p_offset + p_filesz <= len(data):
            info["interpreter"] = data[p_offset:p_offset + p_filesz].split(b"\x00")[0].decode(errors="replace")
        elif p_type == 2:
            info["dynamic"] = True
        elif p_type == 1 and (p_flags & 7) == 7:
            rwx = True
    if rwx:
        obs.append({"id": "elf-rwx-segment"})

    # Section headers: names, and whether a symbol table survives.
    names: list[str] = []
    if e_shoff and e_shnum and e_shstrndx < e_shnum:
        hdr = 64 if is64 else 40

        def sh(i: int):
            off = e_shoff + i * e_shentsize
            if off + hdr > len(data):
                return None
            if is64:
                name, typ, _fl, _addr, offset, size = struct.unpack_from(end + "IIQQQQ", data, off)
            else:
                name, typ, _fl, _addr, offset, size = struct.unpack_from(end + "IIIIII", data, off)
            return name, typ, offset, size

        strtab = sh(e_shstrndx)
        table = b""
        if strtab and strtab[2] + strtab[3] <= len(data) and strtab[3] <= 1 << 20:
            table = data[strtab[2]:strtab[2] + strtab[3]]
        for i in range(min(e_shnum, _MAX_HEADERS)):
            s = sh(i)
            if s is None:
                break
            if s[1] == 2:  # SHT_SYMTAB
                info["stripped"] = False
            if table and s[0] < len(table):
                nm = table[s[0]:table.find(b"\x00", s[0])].decode(errors="replace")
                if nm:
                    names.append(nm)
    info["sections"] = names[:64]
    if e_type in (2, 3) and not e_shnum:
        # Linkers always emit section headers; stripping them entirely is a
        # packer / hand-crafted-binary trait.
        obs.append({"id": "elf-no-section-headers"})
    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]:
        obs.append({"id": "elf-packed-upx"})
    info["observations"] = obs
    return info


# -- Mach-O --------------------------------------------------------------
def _macho_info(data: bytes) -> dict[str, Any] | None:
    if data[:4] in _FAT_MAGICS:
        return _macho_fat(data)
    return _macho_thin(data, 0)


def _macho_fat(data: bytes) -> dict[str, Any] | None:
    is64 = data[:4] == b"\xca\xfe\xba\xbf"
    nfat = struct.unpack_from(">I", data, 4)[0]
    slices: list[dict[str, Any]] = []
    entry = 32 if is64 else 20
    for i in range(min(nfat, 20)):
        off = 8 + i * entry
        if off + entry > len(data):
            break
        if is64:
            _cpu, _sub, offset, _size = struct.unpack_from(">iiQQ", data, off)
        else:
            _cpu, _sub, offset, _size = struct.unpack_from(">iiII", data, off)
        thin = _macho_thin(data, offset) if offset + 28 <= len(data) else None
        if thin:
            slices.append(thin)
    if not slices:
        return {"format": "macho", "universal": True, "architectures": [],
                "observations": [], "signature_embedded": False}
    obs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for s in slices:
        for o in s["observations"]:
            if o["id"] not in seen:
                seen.add(o["id"])
                obs.append(o)
    first = slices[0]
    return {
        "format": "macho", "universal": True,
        "architectures": [s["arch"] for s in slices],
        "arch": "+".join(s["arch"] for s in slices),
        "type": first["type"],
        "signature_embedded": all(s["signature_embedded"] for s in slices),
        "segments": first["segments"],
        "libraries": first["libraries"],
        "observations": obs,
    }


def _macho_thin(data: bytes, base: int) -> dict[str, Any] | None:
    magic = data[base:base + 4]
    if magic not in _MACHO_MAGICS:
        return None
    end, is64 = _MACHO_MAGICS[magic]
    hdr = 32 if is64 else 28
    if base + hdr > len(data):
        return None
    cputype, _sub, filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(end + "IIIIII", data, base + 4)
    info: dict[str, Any] = {
        "format": "macho",
        "universal": False,
        "bits": 64 if is64 else 32,
        "arch": _MACHO_CPUS.get(cputype, hex(cputype)),
        "type": _MACHO_TYPES.get(filetype, str(filetype)),
        "segments": [],
        "libraries": [],
        "signature_embedded": False,
        "encrypted": False,
    }
    obs: list[dict[str, Any]] = []
    off = base + hdr
    rwx: list[str] = []
    for _ in range(min(ncmds, _MAX_HEADERS)):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        base_cmd = cmd & 0x7FFFFFFF
        if base_cmd in (0x1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
            segname = data[off + 8:off + 24].split(b"\x00")[0].decode(errors="replace")
            prot_off = off + (56 if base_cmd == 0x19 else 40)
            if prot_off + 8 <= len(data):
                _maxprot, initprot = struct.unpack_from(end + "ii", data, prot_off)
                info["segments"].append(segname)
                if (initprot & 7) == 7:
                    rwx.append(segname)
        elif base_cmd == 0x1D:  # LC_CODE_SIGNATURE
            info["signature_embedded"] = True
        elif base_cmd in (0xC, 0x18, 0x1F):  # LOAD_DYLIB / WEAK / REEXPORT
            name_off = struct.unpack_from(end + "I", data, off + 8)[0]
            if 0 < name_off < cmdsize:
                lib = data[off + name_off:off + cmdsize].split(b"\x00")[0].decode(errors="replace")
                if len(info["libraries"]) < 64:
                    info["libraries"].append(lib)
        elif base_cmd in (0x21, 0x2C):  # LC_ENCRYPTION_INFO(_64)
            if off + 20 <= len(data) and struct.unpack_from(end + "I", data, off + 16)[0]:
                info["encrypted"] = True
        off += cmdsize
    if rwx:
        obs.append({"id": "macho-rwx-segment", "segments": rwx[:6]})
    if info["type"] in ("executable", "dylib", "bundle") and not info["signature_embedded"] \
            and info["arch"] == "arm64":
        # Apple Silicon refuses to run code that isn't at least ad-hoc signed,
        # so an arm64 image with no signature at all is out of the ordinary.
        obs.append({"id": "macho-unsigned-arm64"})
    info["observations"] = obs
    return info
