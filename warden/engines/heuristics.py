"""Structural / behavioural heuristics.

Signature engines only catch what's already known. Heuristics catch the
*shape* of suspicious files: Windows executables with packer hints, tiny
droppers, script files stuffed with obfuscation, files wearing a fake
double extension, and unusually high-entropy blobs.

None of these is proof of malware on its own, so most are LOW/MEDIUM. They're
meant to make a human (or the GUI) look twice.
"""

from __future__ import annotations

import math
from pathlib import Path

from .. import binfmt
from ..models import Finding, Severity
from .base import ScanContext

# Extensions that are executable/scripting and worth extra scrutiny.
_EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl"}
_SCRIPT_EXTS = {".ps1", ".vbs", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta", ".vbe"}
# Real extension hidden behind a fake-looking one (classic phishing trick).
_LURE_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".mp4"}

_SUSPICIOUS_SCRIPT_TOKENS = (
    "FromBase64String", "-enc", "-EncodedCommand", "IEX", "Invoke-Expression",
    "DownloadString", "DownloadFile", "WebClient", "bitsadmin", "certutil -decode",
    "powershell -nop", "-w hidden", "-windowstyle hidden", "Add-MpPreference",
    "eval(unescape", "document.write(unescape", "ActiveXObject", "WScript.Shell",
    "cmd /c", "vssadmin delete", "bcdedit", "wbadmin delete",
)


# Upper bound so a crafted/huge file can't make an engine hang or balloon memory.
_MAX_SCRIPT_BYTES = 2 * 1024 * 1024     # only token-scan the first 2 MB


class HeuristicsEngine:
    name = "heuristics"

    def available(self) -> bool:
        return True

    @property
    def status(self) -> str:
        return "on" + ("" if binfmt.pefile else " (pefile missing: no PE analysis)")

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        path = ctx.path
        ext = path.suffix.lower()
        data = ctx.data()

        # 1) Fake double extension, e.g. invoice.pdf.exe
        findings += self._double_extension(path, ext)

        # 2) Script content heuristics
        if ext in _SCRIPT_EXTS or _looks_like_text(data):
            findings += self._script_tokens(data)

        # 3) Executable structure (PE / ELF / Mach-O). The parsed metadata is
        #    shared through the context so the scanner can attach it to the
        #    result without parsing the file a second time.
        info = binfmt.binary_info(data, ctx.size)
        ctx.cache["binary"] = info
        if info:
            findings += self._binary_findings(info, ext)

        # 4) High entropy for small executables (possible packed dropper)
        if (ext in _EXECUTABLE_EXTS or info) and 0 < ctx.size <= 5 * 1024 * 1024:
            ent = _entropy(data)
            if ent >= 7.2:
                findings.append(Finding(
                    engine=self.name, name="high-entropy-executable",
                    severity=Severity.LOW,
                    description=f"Executable has high entropy ({ent:.2f}/8.0), often a sign of packing/encryption",
                    meta={"entropy": round(ent, 3)},
                ))
        return findings

    # -- individual checks ------------------------------------------------
    def _double_extension(self, path: Path, ext: str) -> list[Finding]:
        suffixes = [s.lower() for s in path.suffixes]
        if len(suffixes) >= 2 and ext in (_EXECUTABLE_EXTS | _SCRIPT_EXTS):
            inner = suffixes[-2]
            if inner in _LURE_EXTS:
                return [Finding(
                    engine=self.name, name="fake-double-extension",
                    severity=Severity.HIGH,
                    description=f"File poses as '{inner}' but is really '{ext}' ({path.name})",
                    meta={"suffixes": suffixes},
                )]
        return []

    def _script_tokens(self, data: bytes) -> list[Finding]:
        # Bound the work and lowercase ONCE (not once per token).
        try:
            text = data[:_MAX_SCRIPT_BYTES].decode("utf-8", errors="ignore").lower()
        except Exception:  # noqa: BLE001
            return []
        hits = [tok for tok in _SUSPICIOUS_SCRIPT_TOKENS if tok.lower() in text]
        if not hits:
            return []
        sev = Severity.MEDIUM if len(hits) >= 2 else Severity.LOW
        return [Finding(
            engine=self.name, name="suspicious-script-content",
            severity=sev,
            description=f"Script contains {len(hits)} suspicious token(s): {', '.join(hits[:6])}",
            meta={"tokens": hits[:12]},
        )]

    def _binary_findings(self, info: dict, ext: str) -> list[Finding]:
        out: list[Finding] = []
        if info.get("format") == "pe" and info.get("type") == "dll" and ext == ".exe":
            out.append(Finding(
                engine=self.name, name="dll-with-exe-extension", severity=Severity.LOW,
                description="File is a DLL but has a .exe extension"))
        for obs in info.get("observations", []):
            oid = obs.get("id")
            text = _OBSERVATIONS.get(oid)
            if text is None:
                continue
            detail = obs.get("section") or ", ".join(
                (obs.get("imports") or obs.get("sections") or obs.get("segments") or [])[:6])
            out.append(Finding(
                engine=self.name, name=oid, severity=Severity.LOW,
                description=text.format(detail=detail),
                meta={k: v for k, v in obs.items() if k != "id"},
            ))
        return out


# Structural observations from binfmt -> human wording. All LOW: each is a
# reason to look twice, none is proof on its own.
_OBSERVATIONS = {
    "packer-section": "PE contains packer section '{detail}'",
    "risky-imports": "Imports notable APIs: {detail}",
    "pe-writable-executable-section": "PE has section(s) that are both writable and executable: {detail}",
    "elf-rwx-segment": "ELF maps a segment that is readable, writable and executable",
    "elf-no-section-headers": "ELF has no section headers (typical of packed or hand-built binaries)",
    "elf-packed-upx": "ELF is packed with UPX",
    "macho-rwx-segment": "Mach-O has segment(s) that are readable, writable and executable: {detail}",
    "macho-unsigned-arm64": "Apple Silicon Mach-O carries no code signature at all",
}


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(sample) > 0.85


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent
