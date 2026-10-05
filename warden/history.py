"""Scan history: persist each scan/sweep report so results can be reviewed later.

Reports are written as JSON to ``~/.warden/history/`` with a sortable,
timestamped filename. This is what scheduled scans write to (since nobody is
watching the terminal at 3am) and what the GUI dashboard reads to show trends.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import audit
from .config import Config
from .models import ScanReport

_SAFE_ID = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def _text(value: Any, default: str) -> str:
    return value if isinstance(value, str) else default


def _complete(data: dict[str, Any]) -> bool:
    coverage = data.get("coverage")
    return not (isinstance(coverage, dict) and coverage.get("complete") is False)


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


@dataclass(slots=True)
class HistoryEntry:
    id: str
    kind: str          # "scan" | "sweep" | "scheduled"
    when: str
    root: str
    files_scanned: int
    threats: int
    path: str          # on-disk json path
    # False when the scan could not cover everything (unreadable paths, engine
    # errors, cancelled...). A report with no threats is only "clean" if this
    # is True; reports written before the field existed are taken as complete.
    complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "when": self.when, "root": self.root,
            "files_scanned": self.files_scanned, "threats": self.threats,
            "complete": self.complete, "path": self.path,
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
        # Data minimisation: with a retention period set, reports older than it
        # are dropped whenever a new one is saved (setting it IS the consent).
        if self.config.history_retention_days > 0:
            self.expire(self.config.history_retention_days)
        return HistoryEntry(
            id=entry_id, kind=kind, when=report.finished or report.started,
            root=report.root, files_scanned=report.files_scanned,
            threats=len(report.threats), complete=report.coverage_complete, path=str(out),
        )

    def list(self, limit: int | None = None) -> list[HistoryEntry]:
        entries: list[HistoryEntry] = []
        for fp in sorted(self.dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            if not isinstance(data, dict):
                continue        # not a report (damaged or foreign file)
            entries.append(HistoryEntry(
                # The id is always the file name - it is what `load` looks up -
                # never a value read out of the (untrusted) file body.
                id=fp.stem,
                kind=_text(data.get("kind"), "scan"),
                when=_text(data.get("finished") or data.get("started"), ""),
                root=_text(data.get("root"), "?"),
                files_scanned=_count(data.get("files_scanned")),
                threats=_count(data.get("threats")),
                complete=_complete(data),
                path=str(fp),
            ))
            if limit and len(entries) >= limit:
                break
        return entries

    def load(self, entry_id: str) -> dict[str, Any] | None:
        # The id is used in a file name and a glob: allow only the characters
        # our own ids are made of, so it can't traverse or wildcard its way out.
        if not _SAFE_ID.match(str(entry_id)):
            return None
        fp = self.dir / f"{entry_id}.json"
        if not fp.exists():
            # allow prefix / partial id match
            matches = sorted(self.dir.glob(f"{entry_id}*.json"))
            if not matches:
                return None
            fp = matches[0]
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None
        return data if isinstance(data, dict) else None

    def prune(self, keep: int = 50) -> int:
        files = sorted(self.dir.glob("*.json"), reverse=True)
        removed = 0
        for fp in files[keep:]:
            try:
                fp.unlink()
                removed += 1
            except OSError:
                pass
        if removed:
            audit.record("history.prune", self.config, removed=removed, kept=keep)
        return removed

    def expire(self, older_than_days: float) -> int:
        """Delete reports older than ``older_than_days`` (by the timestamp in
        their file name, which Warden wrote - not by anything inside the file)."""
        cutoff = datetime.now(timezone.utc).timestamp() - older_than_days * 86400
        removed = 0
        for fp in self.dir.glob("*.json"):
            m = re.match(r"^(\d{8}T\d{6})", fp.stem)
            if not m:
                continue
            try:
                when = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if when.timestamp() < cutoff:
                try:
                    fp.unlink()
                    removed += 1
                except OSError:
                    pass
        if removed:
            audit.record("history.prune", self.config, removed=removed,
                         older_than_days=older_than_days)
        return removed
