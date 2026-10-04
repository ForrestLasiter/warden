"""Document inspection: Office macros, PDF active content, RTF objects.

Documents are the most common malware delivery vehicle, and the dangerous part
is rarely a byte signature - it's *active content*: a VBA macro that runs on
open, a PDF that launches a program, an RTF carrying an exploit object, a
.docx that pulls its template from a remote server.

This engine looks for that active content structurally:

  * Legacy Office (.doc/.xls/.ppt, OLE compound files): finds VBA projects,
    decompresses the macro source, and looks for auto-run entry points combined
    with process/download/obfuscation primitives.
  * Modern Office (OOXML zip): the same for an embedded ``vbaProject.bin``, plus
    macro-in-a-macro-free-extension and remote-template injection.
  * PDF: JavaScript, launch actions, embedded files.
  * RTF: embedded OLE objects, the Equation Editor exploit pattern.

All parsing is pure Python over bytes already in memory, bounded at every step.
Nothing is executed, rendered, or opened with Office.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile

from ..models import Finding, Severity
from .base import ScanContext

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF

# Hard bounds - a hostile document must not be able to make us spin or balloon.
_MAX_DOC_BYTES = 64 * 1024 * 1024       # don't structurally parse above this
_MAX_OLE_STREAMS = 2048
_MAX_OLE_BYTES = 64 * 1024 * 1024       # total stream bytes materialized
_MAX_CHAIN = 1 << 20                    # sectors followed per chain
_MAX_VBA_OUT = 4 * 1024 * 1024          # decompressed macro source per module
_MAX_VBA_MODULES = 256
_MAX_ZIP_MEMBER = 32 * 1024 * 1024
_MAX_RELS_BYTES = 1 * 1024 * 1024
_MAX_PDF_SCAN = 32 * 1024 * 1024
_MAX_RTF_SCAN = 16 * 1024 * 1024

_MACRO_FREE_EXTS = {".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx", ".ppsx"}

# VBA entry points Office runs without the user asking.
_AUTOEXEC = (
    "autoopen", "autoexec", "autoclose", "autonew", "auto_open", "auto_close",
    "document_open", "document_close", "document_new", "documentopen",
    "workbook_open", "workbook_activate", "workbook_beforeclose",
    "app_documentopen", "app_workbookopen",
)
# Primitives that run programs or fetch content.
_EXEC_TOKENS = (
    "shell(", "shell ", "wscript.shell", "shell.application", "shellexecute",
    "powershell", "cmd.exe", "cmd /c", "mshta", "regsvr32", "rundll32", "certutil",
    "bitsadmin", "createprocess", "winexec", "urldownloadtofile", "msxml2.xmlhttp", "msxml2.serverxmlhttp",
    "winhttp.winhttprequest", "adodb.stream", "internetexplorer.application",
    "virtualalloc", "rtlmovememory", "createthread", "writeprocessmemory",
)
# Obfuscation / staging helpers - suspicious in bulk, not on their own.
_OBFUSCATION_TOKENS = (
    "createobject", "getobject", "callbyname", "strreverse", "chrw(", "chr(",
    "environ(", "frombase64string", "declare function", "declare ptrsafe",
    "savetofile", "responsebody", "kill ",
)

# 0x01 signature byte, a chunk header whose high byte is 0xB? (compressed chunk,
# signature bits 011), a flag byte of zero, then eight literal bytes.
_COMPRESSED_VBA_RE = re.compile(rb"\x01[\x00-\xff][\xb0-\xbf]\x00Attribut", re.S)


class DocumentEngine:
    name = "documents"

    def available(self) -> bool:
        return True

    @property
    def status(self) -> str:
        return "on (Office macros, PDF active content, RTF objects)"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.size > _MAX_DOC_BYTES:
            return []
        data = ctx.data()
        if len(data) < 8:
            return []
        ext = ctx.path.suffix.lower()
        if data[:8] == _OLE_MAGIC:
            return self._ole(data)
        if data[:4] == b"PK\x03\x04":
            return self._ooxml(data, ext)
        if b"%PDF-" in data[:1024]:
            return self._pdf(data)
        if data[:4] == b"{\\rt":
            return self._rtf(data)
        return []

    # -- Office ----------------------------------------------------------
    def _ole(self, data: bytes) -> list[Finding]:
        streams = ole_streams(data)
        if not streams:
            return []
        names = [n.lower() for n, _ in streams]
        findings: list[Finding] = []
        if any(n == "encryptedpackage" for n in names):
            findings.append(self._f(
                "encrypted-office-document", Severity.LOW,
                "Password-protected Office document: its contents could not be inspected "
                "(a common way to slip malware past scanners)"))
        if any("ole10native" in n for n in names):
            findings.append(self._f(
                "ole-embedded-package", Severity.LOW,
                "Document embeds a packaged file object (can carry an executable or script)"))
        has_vba = any(n in ("_vba_project", "dir") or n.startswith("__srp_") for n in names)
        source = extract_vba_source(streams)
        if has_vba or source:
            findings += self._macro_findings(source)
        return findings

    def _ooxml(self, data: bytes, ext: str) -> list[Finding]:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
            return []
        findings: list[Finding] = []
        with zf:
            try:
                infos = zf.infolist()[:5000]
            except Exception:  # noqa: BLE001
                return []
            names = {i.filename for i in infos}
            if "[Content_Types].xml" not in names:
                return []   # an ordinary zip, not an Office document
            for info in infos:
                low = info.filename.lower()
                if low.endswith("vbaproject.bin"):
                    blob = _zip_read(zf, info, _MAX_ZIP_MEMBER)
                    source = extract_vba_source(ole_streams(blob)) if blob else ""
                    findings += self._macro_findings(source)
                    if ext in _MACRO_FREE_EXTS:
                        findings.append(self._f(
                            "office-macro-extension-mismatch", Severity.MEDIUM,
                            f"File is named '{ext}' (a macro-free format) but contains a VBA macro project",
                            member=info.filename))
                elif low.endswith(".rels"):
                    rels = _zip_read(zf, info, _MAX_RELS_BYTES)
                    if rels:
                        findings += self._rels_findings(rels, info.filename)
        return findings

    def _rels_findings(self, rels: bytes, member: str) -> list[Finding]:
        out: list[Finding] = []
        text = rels.decode("utf-8", errors="ignore")
        for m in re.finditer(r"<Relationship\b[^>]*>", text):
            tag = m.group(0)
            if 'TargetMode="External"' not in tag:
                continue
            target = re.search(r'Target="([^"]*)"', tag)
            rtype = re.search(r'Type="([^"]*)"', tag)
            url = target.group(1) if target else ""
            kind = (rtype.group(1) if rtype else "").rsplit("/", 1)[-1].lower()
            if not re.match(r"(?i)^(https?|ftp|file|\\\\)", url):
                continue
            if kind == "attachedtemplate":
                out.append(self._f(
                    "office-remote-template", Severity.HIGH,
                    "Document loads its template from a remote location when opened "
                    "(template injection - the remote file can carry macros)",
                    target=url[:200], member=member))
            elif kind in ("oleobject", "frame", "subdocument"):
                out.append(self._f(
                    "office-external-object", Severity.MEDIUM,
                    f"Document links an external {kind} that is fetched when opened",
                    target=url[:200], member=member))
        return out[:10]

    def _macro_findings(self, source: str) -> list[Finding]:
        low = source.lower()
        auto = sorted({t for t in _AUTOEXEC if t in low})
        execs = sorted({t for t in _EXEC_TOKENS if t in low})
        obfus = sorted({t for t in _OBFUSCATION_TOKENS if t in low})
        meta = {"autoexec": auto, "execution": execs[:12], "obfuscation": obfus[:12],
                "source_bytes": len(source)}
        if auto and execs:
            return [self._f(
                "office-macro-autoexec-suspicious", Severity.HIGH,
                f"Macro runs automatically ({', '.join(auto[:3])}) and can launch programs or "
                f"download content ({', '.join(execs[:4])})", **meta)]
        if execs and (len(execs) >= 2 or obfus):
            return [self._f(
                "office-macro-suspicious", Severity.MEDIUM,
                f"Macro uses process/download primitives ({', '.join(execs[:4])})", **meta)]
        if auto:
            return [self._f(
                "office-macro-autoexec", Severity.LOW,
                f"Document contains a macro that runs automatically ({', '.join(auto[:3])})", **meta)]
        return [self._f(
            "office-macros-present", Severity.LOW,
            "Document contains VBA macros", **meta)]

    # -- PDF -------------------------------------------------------------
    def _pdf(self, data: bytes) -> list[Finding]:
        body = data[:_MAX_PDF_SCAN]
        # Drop stream payloads (compressed/binary data) so random bytes inside
        # them can't spell out a name by chance; names live in the object
        # dictionaries between streams.
        body = re.sub(rb"stream\r?\n.*?endstream", b"", body, flags=re.S)
        # Names can hide behind #xx hex escapes ("/J#61vaScript"); normalize.
        if b"#" in body:
            body = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), body)

        def has(name: bytes) -> bool:
            return re.search(rb"/" + name + rb"(?![A-Za-z0-9])", body) is not None

        findings: list[Finding] = []
        if has(b"Launch"):
            findings.append(self._f(
                "pdf-launch-action", Severity.MEDIUM,
                "PDF contains a Launch action (can start a program when opened)"))
        js = has(b"JavaScript") or has(b"JS")
        auto = has(b"OpenAction") or has(b"AA")
        if js:
            findings.append(self._f(
                "pdf-javascript", Severity.LOW,
                "PDF contains JavaScript" + (" and an automatic action" if auto else ""),
                automatic_action=auto))
        if has(b"EmbeddedFile"):
            findings.append(self._f(
                "pdf-embedded-file", Severity.LOW, "PDF carries an embedded file attachment"))
        if has(b"XFA"):
            findings.append(self._f(
                "pdf-xfa-form", Severity.INFO, "PDF uses XFA forms (scriptable form technology)"))
        return findings

    # -- RTF -------------------------------------------------------------
    def _rtf(self, data: bytes) -> list[Finding]:
        body = data[:_MAX_RTF_SCAN]
        low = body.lower()
        if b"\\objdata" not in low and b"\\object" not in low:
            return []
        # Object data is hex text, often broken up with whitespace to dodge
        # signatures - squeeze it before matching.
        squeezed = re.sub(rb"[\s{}]+", b"", low)
        findings: list[Finding] = []
        # "Equation.3" in hex == the Equation Editor CLSID route (CVE-2017-11882).
        if b"4571756174696f6e2e33" in squeezed or b"0002ce02" in squeezed:
            findings.append(self._f(
                "rtf-equation-editor-object", Severity.HIGH,
                "RTF embeds an Equation Editor object - the classic CVE-2017-11882 exploit carrier"))
        elif b"\\objupdate" in low:
            findings.append(self._f(
                "rtf-auto-update-object", Severity.MEDIUM,
                "RTF embeds an object that updates automatically on open (\\objupdate)"))
        else:
            findings.append(self._f(
                "rtf-embedded-object", Severity.LOW, "RTF embeds an OLE object"))
        return findings

    def _f(self, name: str, severity: Severity, description: str, **meta) -> Finding:
        return Finding(engine=self.name, name=name, severity=severity,
                       description=description, meta=dict(meta))


# -- helpers -------------------------------------------------------------
def _zip_read(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    """Read one zip member, never trusting its declared size."""
    try:
        with zf.open(info) as fh:
            blob = fh.read(limit + 1)
    except Exception:  # noqa: BLE001 - encrypted, corrupt, unsupported method
        return b""
    return blob if len(blob) <= limit else b""


def ole_streams(data: bytes) -> list[tuple[str, bytes]]:
    """All streams of an OLE compound file as (name, bytes). Never raises.

    A compact reader for the Compound File Binary format: header -> DIFAT ->
    FAT -> directory -> (mini)streams, with every chain length and total size
    bounded so a cyclic or oversized FAT can't hang the scan.
    """
    try:
        return _ole_streams(data)
    except Exception:  # noqa: BLE001 - malformed container
        return []


def _ole_streams(data: bytes) -> list[tuple[str, bytes]]:
    if len(data) < 512 or data[:8] != _OLE_MAGIC:
        return []
    sector_shift, mini_shift = struct.unpack_from("<HH", data, 30)
    if sector_shift not in (9, 12) or mini_shift != 6:
        return []
    ssize, msize = 1 << sector_shift, 1 << mini_shift
    (_ndir, nfat, first_dir, _txn, mini_cutoff, first_minifat, _nminifat,
     first_difat, ndifat) = struct.unpack_from("<IIIIIIIII", data, 40)
    per = ssize // 4

    def sector(n: int) -> bytes:
        off = (n + 1) << sector_shift
        return data[off:off + ssize]

    # DIFAT: 109 entries in the header, then a chain of DIFAT sectors.
    fat_sectors = [s for s in struct.unpack_from("<109I", data, 76) if s < _ENDOFCHAIN]
    nxt, hops = first_difat, 0
    while nxt < _ENDOFCHAIN and hops < min(ndifat, 4096):
        blk = sector(nxt)
        if len(blk) < ssize:
            break
        vals = struct.unpack(f"<{per}I", blk)
        fat_sectors += [s for s in vals[:-1] if s < _ENDOFCHAIN]
        nxt, hops = vals[-1], hops + 1
    fat: list[int] = []
    for s in fat_sectors[:min(max(nfat, 1), 65536)]:
        blk = sector(s)
        if len(blk) < ssize:
            blk = blk.ljust(ssize, b"\xff")
        fat.extend(struct.unpack(f"<{per}I", blk))

    budget = [_MAX_OLE_BYTES]

    def chain(start: int, table: list[int]) -> list[int]:
        out: list[int] = []
        seen: set[int] = set()
        n = start
        while n < _ENDOFCHAIN and n < len(table) and n not in seen and len(out) < _MAX_CHAIN:
            seen.add(n)
            out.append(n)
            n = table[n]
        return out

    def read_chain(start: int, size: int | None = None) -> bytes:
        parts: list[bytes] = []
        total = 0
        for n in chain(start, fat):
            blk = sector(n)
            parts.append(blk)
            total += len(blk)
            if (size is not None and total >= size) or total > budget[0]:
                break
        buf = b"".join(parts)
        budget[0] -= len(buf)
        return buf if size is None else buf[:size]

    directory = read_chain(first_dir)
    entries: list[tuple[str, int, int, int]] = []
    for off in range(0, min(len(directory), _MAX_OLE_STREAMS * 128), 128):
        ent = directory[off:off + 128]
        if len(ent) < 128:
            break
        name_len = struct.unpack_from("<H", ent, 64)[0]
        etype = ent[66]
        if etype not in (1, 2, 5) or name_len < 2 or name_len > 64:
            continue
        name = ent[:name_len - 2].decode("utf-16-le", errors="replace")
        start = struct.unpack_from("<I", ent, 116)[0]
        size = struct.unpack_from("<Q", ent, 120)[0]
        if sector_shift == 9:
            size &= 0xFFFFFFFF
        entries.append((name, etype, start, size))

    root = next((e for e in entries if e[1] == 5), None)
    ministream = read_chain(root[2], min(root[3], _MAX_OLE_BYTES)) if root else b""
    minifat: list[int] = []
    if first_minifat < _ENDOFCHAIN:
        raw = read_chain(first_minifat)
        minifat = list(struct.unpack(f"<{len(raw) // 4}I", raw[:len(raw) // 4 * 4]))

    out: list[tuple[str, bytes]] = []
    for name, etype, start, size in entries:
        if etype != 2 or budget[0] <= 0:
            continue
        size = min(size, _MAX_OLE_BYTES)
        if size < mini_cutoff:
            parts = [ministream[n * msize:(n + 1) * msize] for n in chain(start, minifat)]
            blob = b"".join(parts)[:size]
            budget[0] -= len(blob)
        else:
            blob = read_chain(start, size)
        out.append((name, blob))
    return out


def vba_decompress(data: bytes, offset: int = 0, max_out: int = _MAX_VBA_OUT) -> bytes:
    """Decompress an MS-OVBA "compressed container" starting at ``offset``.

    Tolerant by design: on any malformed chunk it returns what it has so far.
    """
    if offset >= len(data) or data[offset] != 0x01:
        return b""
    out = bytearray()
    pos = offset + 1
    n = len(data)
    while pos + 2 <= n and len(out) < max_out:
        header = data[pos] | (data[pos + 1] << 8)
        if (header >> 12) & 0x07 != 0b011:
            break
        chunk_end = min(pos + (header & 0x0FFF) + 3, n)
        pos += 2
        if not header & 0x8000:            # stored (uncompressed) chunk
            out += data[pos:pos + 4096]
            pos += 4096
            continue
        chunk_start = len(out)
        while pos < chunk_end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not (flags >> bit) & 1:
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    pos = chunk_end
                    break
                token = data[pos] | (data[pos + 1] << 8)
                pos += 2
                diff = len(out) - chunk_start
                if diff <= 0:
                    return bytes(out)
                bits = max((diff - 1).bit_length(), 4)
                length_mask = 0xFFFF >> bits
                length = (token & length_mask) + 3
                back = ((token & ~length_mask & 0xFFFF) >> (16 - bits)) + 1
                if back > diff:
                    return bytes(out)
                for _ in range(length):
                    out.append(out[-back])
    return bytes(out[:max_out])


def extract_vba_source(streams: list[tuple[str, bytes]]) -> str:
    """Concatenated, decompressed VBA module source found in OLE streams.

    Module streams hold p-code followed by a compressed container whose source
    always begins with an ``Attribute VB_...`` line, so we locate containers by
    that signature instead of walking the (attacker-controllable) dir stream.
    """
    chunks: list[str] = []
    modules = 0
    for _name, blob in streams:
        for m in _COMPRESSED_VBA_RE.finditer(blob):
            if modules >= _MAX_VBA_MODULES:
                break
            src = vba_decompress(blob, m.start())
            if src:
                modules += 1
                chunks.append(src.decode("latin-1", errors="replace"))
    return "\n".join(chunks)
