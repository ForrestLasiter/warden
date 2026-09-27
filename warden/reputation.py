"""Online hash reputation lookups.

Off by default and opt-in: enabling it sends a file's *hash* (never the file
itself) to an online service to ask whether it's known malware. Two providers:

  * ``cymru`` (default, no key needed) - Team Cymru's Malware Hash Registry,
    queried over DNS-over-HTTPS. Returns a last-seen time and an antivirus
    detection percentage for known-bad files. Works out of the box.
  * ``virustotal`` (needs a free API key) - VirusTotal's file report, which
    aggregates 70+ engines. Set the key via ``WARDEN_VT_API_KEY`` or the
    ``virustotal_api_key`` config field. Richer, but rate-limited on the free
    tier (~4 lookups/min), so Warden caps and caches aggressively.

Results are cached to ``~/.warden/cache/reputation.json`` so repeat scans don't
re-query. Every network failure fails *open* (no finding), never crashing a scan.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

from .config import Config

_CYMRU_HOST = "malware.hash.cymru.com"
_DOH_URL = "https://cloudflare-dns.com/dns-query"
_VT_URL = "https://www.virustotal.com/api/v3/files/"


@dataclass(slots=True)
class ReputationResult:
    known: bool                 # did the provider have a record?
    malicious: bool             # does that record indicate malware?
    source: str                 # "cymru" | "virustotal"
    detections: str = ""        # human-readable detection summary
    detail: dict[str, Any] | None = None


class OnlineReputation:
    """Provider-agnostic reputation lookups with cache + rate limiting."""

    def __init__(self, config: Config | None = None, *, max_lookups: int = 60):
        self.config = config or Config.load()
        self.config.ensure_dirs()
        self.cache_path = self.config.data_dir / "cache" / "reputation.json"
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Prefer VirusTotal when a key is present (richer); else keyless Cymru.
        self._vt_key = (
            os.environ.get("WARDEN_VT_API_KEY")
            or getattr(self.config, "virustotal_api_key", "")
            or ""
        ).strip()
        self.provider = "virustotal" if self._vt_key else "cymru"

        self._cache = self._load_cache()
        self._mem: dict[str, ReputationResult] = {}
        self._budget = max_lookups          # network calls allowed per run
        self._disabled = httpx is None      # hard-off if httpx missing
        self._last_call = 0.0
        # VirusTotal free tier is ~4/min; space calls out a little.
        self._min_interval = 15.0 if self.provider == "virustotal" else 0.0

    @property
    def available(self) -> bool:
        return not self._disabled

    @property
    def status(self) -> str:
        if self._disabled:
            return "unavailable (httpx missing)"
        return f"{self.provider}" + (" (VT key set)" if self.provider == "virustotal" else " (keyless)")

    # -- cache ------------------------------------------------------------
    def _load_cache(self) -> dict[str, dict]:
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_cache(self) -> None:
        try:
            self.cache_path.write_text(json.dumps(self._cache, indent=0), encoding="utf-8")
        except OSError:
            pass

    # -- lookup -----------------------------------------------------------
    def check(self, sha256: str | None, sha1: str | None) -> ReputationResult | None:
        if self._disabled or not (sha256 or sha1):
            return None
        key = f"{self.provider}:{sha256 or sha1}"
        if key in self._mem:
            return self._mem[key]
        if key in self._cache:
            c = self._cache[key]
            res = ReputationResult(**c)
            self._mem[key] = res
            return res
        if self._budget <= 0:
            return None

        # rate-limit spacing (VT); harmless for cymru
        if self._min_interval:
            wait = self._min_interval - (time.time() - self._last_call)
            if wait > 0:
                # Don't stall a scan for long; if we'd have to wait, skip instead.
                return None

        self._budget -= 1
        self._last_call = time.time()
        try:
            if self.provider == "virustotal":
                res = _vt_lookup(sha256, self._vt_key)
            else:
                res = _cymru_lookup(sha1)
        except Exception:  # noqa: BLE001 - fail open
            res = None

        if res is not None:
            self._mem[key] = res
            self._cache[key] = {
                "known": res.known, "malicious": res.malicious,
                "source": res.source, "detections": res.detections,
            }
            self._save_cache()
        return res


# -- providers -----------------------------------------------------------
def _cymru_lookup(sha1: str | None) -> ReputationResult | None:
    if not sha1:
        return None
    name = f"{sha1.lower()}.{_CYMRU_HOST}"
    r = httpx.get(
        _DOH_URL, params={"name": name, "type": "TXT"},
        headers={"accept": "application/dns-json"}, timeout=6.0,
    )
    if r.status_code != 200:
        return None
    data = r.json()
    answers = data.get("Answer") or []
    for ans in answers:
        txt = str(ans.get("data", "")).strip().strip('"')
        # Format: "<last_seen_epoch> <detection_percent>"
        parts = txt.split()
        if len(parts) == 2 and parts[1].isdigit():
            pct = int(parts[1])
            return ReputationResult(
                known=True, malicious=True, source="cymru",
                detections=f"{pct}% AV detection (Team Cymru MHR)",
                detail={"last_seen": parts[0], "detection_pct": pct},
            )
    # NXDOMAIN / no TXT => not in the registry (not necessarily clean).
    return ReputationResult(known=False, malicious=False, source="cymru")


def _vt_lookup(sha256: str | None, api_key: str) -> ReputationResult | None:
    if not sha256:
        return None
    r = httpx.get(_VT_URL + sha256, headers={"x-apikey": api_key}, timeout=10.0)
    if r.status_code == 404:
        return ReputationResult(known=False, malicious=False, source="virustotal")
    if r.status_code == 429:
        return None  # rate limited; fail open
    if r.status_code != 200:
        return None
    stats = (r.json().get("data", {}).get("attributes", {})
             .get("last_analysis_stats", {}))
    mal = int(stats.get("malicious", 0))
    susp = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    return ReputationResult(
        known=True, malicious=(mal + susp) > 0, source="virustotal",
        detections=f"{mal + susp}/{total} engines flagged it (VirusTotal)",
        detail=stats,
    )
