"""Hash-reputation engine.

Checks each file's SHA-256 against:
  1. A local denylist of known-bad hashes (``malware_hashes.txt`` in the
     bundled and user rules dirs), one hex digest per line (``#`` comments ok).
  2. Optionally, a remote reputation API (opt-in only; disabled by default so
     nothing leaves the machine unless the user turns it on).

The local list is the workhorse and needs no network. Users can drop threat-
intel hash feeds (e.g. from abuse.ch) into ``~/.warden/rules/``.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding, Severity
from .base import ScanContext

_HASH_FILENAMES = ("malware_hashes.txt", "hashes.txt")

# Only these file types are worth an online lookup - keeps query volume (and API
# rate-limit pressure) sane while covering the formats malware actually uses.
_ONLINE_CANDIDATE_EXTS = {
    ".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".msi", ".ocx",
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta", ".jar",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf",
    ".zip", ".rar", ".7z", ".iso", ".lnk",
}


class HashEngine:
    name = "hash"

    def __init__(self, hash_dirs: list[Path], reputation=None):
        self._bad: dict[str, str] = {}  # sha256 -> label
        self._reputation = reputation   # OnlineReputation | None
        self._load(hash_dirs)

    def _load(self, hash_dirs: list[Path]) -> None:
        for d in hash_dirs:
            if not d or not d.exists():
                continue
            for fname in _HASH_FILENAMES:
                fp = d / fname
                if not fp.exists():
                    continue
                try:
                    for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Allow "hash  label" or "hash,label" or bare hash.
                        parts = line.replace(",", " ").split(None, 1)
                        digest = parts[0].lower()
                        if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                            label = parts[1] if len(parts) > 1 else "known-malware"
                            self._bad[digest] = label
                except OSError:
                    continue

    @property
    def _online(self) -> bool:
        return self._reputation is not None and self._reputation.available

    def available(self) -> bool:
        return bool(self._bad) or self._online

    @property
    def status(self) -> str:
        bits = [f"{len(self._bad)} known-bad hash(es)"]
        if self._online:
            bits.append(f"online: {self._reputation.status}")
        return ", ".join(bits)

    def scan(self, ctx: ScanContext) -> list[Finding]:
        digest = ctx.sha256()
        if not digest:
            return []
        findings: list[Finding] = []
        label = self._bad.get(digest)
        if label:
            findings.append(Finding(
                engine=self.name,
                name=label,
                severity=Severity.CRITICAL,
                description=f"File hash matches a known-malware entry ({label})",
                meta={"sha256": digest, "source": "local-denylist"},
            ))

        # Online reputation - opt-in, candidate file types only, cached.
        # Never for in-memory content (archive members): one zip could otherwise
        # fan out into thousands of lookups.
        if (self._online and not label and not ctx.in_memory
                and ctx.path.suffix.lower() in _ONLINE_CANDIDATE_EXTS):
            result = self._reputation.check(digest, ctx.sha1())
            if result and result.malicious:
                findings.append(Finding(
                    engine=self.name,
                    name=f"online-reputation-{result.source}",
                    severity=Severity.CRITICAL,
                    description=f"Known malware by online reputation: {result.detections}",
                    meta={"sha256": digest, "source": result.source, **(result.detail or {})},
                ))
        return findings
