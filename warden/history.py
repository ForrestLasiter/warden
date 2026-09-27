"""Scan history: persist each scan/sweep report so results can be reviewed later.

Reports are written as JSON to ``~/.warden/history/`` with a sortable,
timestamped filename. This is what scheduled scans write to (since nobody is
watching the terminal at 3am) and what the GUI dashboard reads to show trends.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .models import ScanReport


@dataclass(slots=True)
class HistoryEntry:
    id: str
    kind: str          # "scan" | "sweep" | "scheduled"
    when: str
    root: str
    files_scanned: int
    threats: int
    path: str          # on-disk json path

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "when": self.when, "root": self.root,
            "files_scanned": self.files_scanned, "threats": self.threats, "path": self.path,
        }


class History:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.config.ensure_dirs()
        self.dir = self.config.history_dir

    def save(self, report: ScanReport, *, kind: str = "scan") -> HistoryEntry:
        # Sub-second precision so rapid successive saves don't overwrite each
        # other (whole-second names collided and silently lost history).
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        entry_id = f"{ts}_{kind}"
        out = self.dir / f"{entry_id}.json"
        payload = {"id": entry_id, "kind": kind, **report.to_dict()}
        from .storage import atomic_write_json
        atomic_write_json(out, payload)
        return HistoryEntry(
            id=entry_id, kind=kind, when=report.finished or report.started,
            root=report.root, files_scanned=report.files_scanned,
            threats=len(report.threats), path=str(out),
        )

    def list(self, limit: int | None = None) -> list[HistoryEntry]:
        entries: list[HistoryEntry] = []
        for fp in sorted(self.dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            entries.append(HistoryEntry(
                id=data.get("id", fp.stem),
                kind=data.get("kind", "scan"),
                when=data.get("finished") or data.get("started", ""),
                root=data.get("root", "?"),
                files_scanned=data.get("files_scanned", 0),
                threats=data.get("threats", 0),
                path=str(fp),
            ))
            if limit and len(entries) >= limit:
                break
        return entries

    def load(self, entry_id: str) -> dict[str, Any] | None:
        fp = self.dir / f"{entry_id}.json"
        if not fp.exists():
            # allow prefix / partial id match
            matches = list(self.dir.glob(f"{entry_id}*.json"))
            if not matches:
                return None
            fp = matches[0]
        try:
            return json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def prune(self, keep: int = 50) -> int:
        files = sorted(self.dir.glob("*.json"), reverse=True)
        removed = 0
        for fp in files[keep:]:
            try:
                fp.unlink()
                removed += 1
            except OSError:
                pass
        return removed
