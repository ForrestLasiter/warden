"""Runtime configuration and on-disk paths.

Config is loaded from ``~/.warden/config.json`` if present, else sensible
defaults. Nothing here requires the file to exist.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .models import default_data_dir

# Files larger than this are hashed but not deep-scanned by content engines
# (YARA/heuristics), to keep full-drive scans fast. Override in config.
DEFAULT_MAX_SCAN_BYTES = 100 * 1024 * 1024  # 100 MB

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
        for p in (self.data_dir, self.quarantine_dir, self.history_dir,
                  self.rules_user_dir, self.cache_dir):
            p.mkdir(parents=True, exist_ok=True)

    # Persistence ---------------------------------------------------------
    @classmethod
    def load(cls, data_dir: Path | None = None) -> "Config":
        cfg = cls(data_dir=data_dir or default_data_dir())
        path = cfg.config_path
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                raw = {}
            cfg.max_scan_bytes = int(raw.get("max_scan_bytes", cfg.max_scan_bytes))
            cfg.follow_symlinks = bool(raw.get("follow_symlinks", cfg.follow_symlinks))
            cfg.use_clamav = bool(raw.get("use_clamav", cfg.use_clamav))
            cfg.online_hash_lookup = bool(raw.get("online_hash_lookup", cfg.online_hash_lookup))
            cfg.virustotal_api_key = str(raw.get("virustotal_api_key", cfg.virustotal_api_key))
            if "skip_extensions" in raw:
                cfg.skip_extensions = {e.lower() for e in raw["skip_extensions"]}
        return cfg

    def save(self) -> None:
        self.ensure_dirs()
        data = {
            "max_scan_bytes": self.max_scan_bytes,
            "follow_symlinks": self.follow_symlinks,
            "use_clamav": self.use_clamav,
            "online_hash_lookup": self.online_hash_lookup,
            "virustotal_api_key": self.virustotal_api_key,
            "skip_extensions": sorted(self.skip_extensions),
        }
        self.config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# Rules bundled with the package (read-only, shipped with Warden).
BUNDLED_RULES_DIR = Path(__file__).parent / "rules"
