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

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None  # type: ignore

from ..models import Finding, Severity
from .base import ScanContext

# Extensions that are executable/scripting and worth extra scrutiny.
_EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl"}
_SCRIPT_EXTS = {".ps1", ".vbs", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta", ".vbe"}
# Real extension hidden behind a fake-looking one (classic phishing trick).
_LURE_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".mp4"}

# Known packer section names -> a hint that the binary is packed/obfuscated.
_PACKER_SECTIONS = {
    b"UPX0", b"UPX1", b"UPX2", b".aspack", b".adata", b"ASPack", b".nsp0",
    b".nsp1", b"FSG!", b".petite", b"pebundle", b"MPRESS1", b"MPRESS2",
    b".themida", b".vmp0", b".vmp1", b".enigma1",
}

_SUSPICIOUS_SCRIPT_TOKENS = (
    "FromBase64String", "-enc", "-EncodedCommand", "IEX", "Invoke-Expression",
    "DownloadString", "DownloadFile", "WebClient", "bitsadmin", "certutil -decode",
    "powershell -nop", "-w hidden", "-windowstyle hidden", "Add-MpPreference",
    "eval(unescape", "document.write(unescape", "ActiveXObject", "WScript.Shell",
    "cmd /c", "vssadmin delete", "bcdedit", "wbadmin delete",
)


class HeuristicsEngine:
    name = "heuristics"

    def available(self) -> bool:
        return True

    @property
    def status(self) -> str:
        return "on" + ("" if pefile else " (pefile missing: no PE analysis)")

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

        # 3) PE structural heuristics
        if data[:2] == b"MZ" and pefile is not None:
            findings += self._pe_checks(data, ext)

        # 4) High entropy for small executables (possible packed dropper)
        if ext in _EXECUTABLE_EXTS and 0 < ctx.size <= 5 * 1024 * 1024:
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
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            return []
        hits = [tok for tok in _SUSPICIOUS_SCRIPT_TOKENS if tok.lower() in text.lower()]
        if not hits:
            return []
        sev = Severity.MEDIUM if len(hits) >= 2 else Severity.LOW
        return [Finding(
            engine=self.name, name="suspicious-script-content",
            severity=sev,
            description=f"Script contains {len(hits)} suspicious token(s): {', '.join(hits[:6])}",
            meta={"tokens": hits[:12]},
        )]

    def _pe_checks(self, data: bytes, ext: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            pe = pefile.PE(data=data, fast_load=True)
        except Exception:  # noqa: BLE001 - not a valid PE
            return findings
        try:
            # Packer section names
            for section in pe.sections:
                raw = section.Name.rstrip(b"\x00")
                if raw in _PACKER_SECTIONS or raw.upper().startswith(b"UPX"):
                    findings.append(Finding(
                        engine=self.name, name="packer-section",
                        severity=Severity.LOW,
                        description=f"PE contains packer section '{raw.decode(errors='replace')}'",
                        meta={"section": raw.decode(errors="replace")},
                    ))
                    break

            # Executable masquerading as a DLL or vice versa vs. characteristics
            characteristics = getattr(pe.FILE_HEADER, "Characteristics", 0)
            is_dll = bool(characteristics & 0x2000)
            if is_dll and ext == ".exe":
                findings.append(Finding(
                    engine=self.name, name="dll-with-exe-extension",
                    severity=Severity.LOW,
                    description="File is a DLL but has a .exe extension",
                ))

            # Very small PE with imports pulling network/exec APIs = dropper-ish.
            try:
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
                ])
                risky = _risky_imports(pe)
                if risky:
                    findings.append(Finding(
                        engine=self.name, name="risky-imports",
                        severity=Severity.LOW,
                        description=f"Imports notable APIs: {', '.join(sorted(risky)[:6])}",
                        meta={"imports": sorted(risky)},
                    ))
            except Exception:  # noqa: BLE001
                pass
        finally:
            pe.close()
        return findings


def _risky_imports(pe) -> set[str]:
    risky_names = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "SetWindowsHookEx", "URLDownloadToFile", "WinExec", "ShellExecuteA",
        "CreateProcessA", "InternetOpenA", "InternetReadFile", "CryptEncrypt",
        "RegSetValueExA", "GetProcAddress", "LoadLibraryA", "IsDebuggerPresent",
    }
    found: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                nm = imp.name.decode(errors="replace")
                if nm in risky_names:
                    found.add(nm)
    return found


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
