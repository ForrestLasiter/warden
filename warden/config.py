"""Runtime configuration and on-disk paths.

Config is loaded from ``~/.warden/config.json`` if present, else sensible
defaults. Nothing here requires the file to exist.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import default_data_dir
from .storage import atomic_write_json, secure_dir

# Files larger than this are hashed but not deep-scanned by content engines
# (YARA/heuristics), to keep full-drive scans fast. Override in config.
DEFAULT_MAX_SCAN_BYTES = 100 * 1024 * 1024  # 100 MB
MIN_SCAN_BYTES = 64 * 1024               # 64 KB floor
MAX_SCAN_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB ceiling


def _clamp_int(value, default: int, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _as_bool(value, default: bool) -> bool:
    """Coerce a config value to bool, handling JSON true/false AND the common
    hand-edited string forms so `"false"` doesn't read as truthy True."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off", ""):
            return False
    if value is None:
        return default
    return bool(value)

# Extensions worth deep content scanning. Everything still gets hashed.
# Empty set here means "scan everything"; we instead skip a known-huge/binary
# media denylist below by default.
SKIP_EXTENSIONS = {
    ".mp4", ".mkv", ".avi", ".mov", ".mp3", ".flac", ".wav",
    ".iso", ".vmdk", ".vdi", ".qcow2",
}


@dataclass(slots=True)
class Config:
    data_dir: Path = field(default_factory=default_data_dir)
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES
    follow_symlinks: bool = False
    use_clamav: bool = True          # used only if clam binaries are found
    online_hash_lookup: bool = False  # opt-in; sends file hashes to a remote API
    virustotal_api_key: str = ""      # optional; enables the richer VT provider
    skip_extensions: set[str] = field(default_factory=lambda: set(SKIP_EXTENSIONS))

    # Derived paths -------------------------------------------------------
    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def history_dir(self) -> Path:
        return self.data_dir / "history"

    @property
    def rules_user_dir(self) -> Path:
        return self.data_dir / "rules"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def config_path(self) -> Path:
        return self.data_dir / "config.json"

    def ensure_dirs(self) -> None:
        # The data dir can hold the VirusTotal key and quarantined malware, so
        # restrict it to the owner on POSIX (best-effort; no-op on Windows).
        secure_dir(self.data_dir)
        secure_dir(self.quarantine_dir)
        for p in (self.history_dir, self.rules_user_dir, self.cache_dir):
            p.mkdir(parents=True, exist_ok=True)

    # Persistence ---------------------------------------------------------
    @classmethod
    def load(cls, data_dir: Path | None = None) -> Config:
        cfg = cls(data_dir=data_dir or default_data_dir())
        path = cfg.config_path
        if not path.exists():
            return cfg
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
        # Every field is validated/coerced with a fallback so a malformed or
        # hostile config.json can never crash Warden or set a pathological limit.
        cfg.max_scan_bytes = _clamp_int(
            raw.get("max_scan_bytes"), cfg.max_scan_bytes, MIN_SCAN_BYTES, MAX_SCAN_BYTES)
        cfg.follow_symlinks = _as_bool(raw.get("follow_symlinks"), cfg.follow_symlinks)
        cfg.use_clamav = _as_bool(raw.get("use_clamav"), cfg.use_clamav)
        cfg.online_hash_lookup = _as_bool(raw.get("online_hash_lookup"), cfg.online_hash_lookup)
        cfg.virustotal_api_key = str(raw.get("virustotal_api_key", cfg.virustotal_api_key) or "")
        exts = raw.get("skip_extensions")
        if isinstance(exts, (list, tuple, set)):
            cfg.skip_extensions = {str(e).lower() for e in exts if isinstance(e, str)}
        return cfg

    def save(self) -> None:
        self.ensure_dirs()
        data = {
            "max_scan_bytes": self.max_scan_bytes,
            "follow_symlinks": self.follow_symlinks,
            "use_clamav": self.use_clamav,
            "online_hash_lookup": self.online_hash_lookup,
            "skip_extensions": sorted(self.skip_extensions),
        }
        # The VirusTotal key is NOT written here anymore - it lives in the OS
        # secret store (see warden/secrets.py). Saving scrubs any legacy
        # plaintext key from config.json. Still owner-only, and atomic.
        atomic_write_json(self.config_path, data, mode=0o600)


# Rules bundled with the package (read-only, shipped with Warden).
BUNDLED_RULES_DIR = Path(__file__).parent / "rules"
