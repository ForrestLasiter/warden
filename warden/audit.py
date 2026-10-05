"""Audit trail: an append-only, tamper-evident record of what Warden did.

Security frameworks (SOC 2 CC7.2, ISO/IEC 27001 A.8.15, HIPAA 164.312(b), PCI DSS
10.2, NIST 800-53 AU-2/AU-9) all ask the same thing of a security tool: *show me
what it did, when, on whose behalf, and that the record hasn't been edited.*
Scan history answers "what was found"; this answers "what was done" - scans run,
files quarantined / restored / deleted, settings changed, rules installed,
schedules created.

Format: ``~/.warden/audit/audit.jsonl``, one JSON object per line::

    {"seq": 12, "ts": "...", "event": "quarantine.restore", "actor": {...},
     "details": {...}, "prev": "<hash of entry 11>", "hash": "<sha256>"}

Each entry's ``hash`` covers its own content *and* the previous entry's hash, so
editing, deleting or reordering any earlier line breaks every hash after it.
``warden audit verify`` re-walks the chain.

What this does and does not prove
---------------------------------
It is **tamper-evident, not tamper-proof**. Anyone who can write to the file as
you can rewrite the whole chain consistently. The chain reliably exposes
accidental damage and casual edits; to resist a determined local attacker, ship
the log somewhere they can't reach (JSON Lines is what log collectors and SIEMs
ingest) or record the head hash that ``warden audit verify`` prints elsewhere.

Privacy: entries contain file paths, the OS user name and the host name. They
never contain file contents, secrets, or API keys. The log never leaves the
machine. Turn it off with ``warden config set audit_log false``.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import sys
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .models import now_iso
from .storage import file_lock, fsync_dir, secure_dir

GENESIS = "0" * 64
_MAX_DETAIL_CHARS = 2000        # one runaway value can't bloat the log
_MAX_LINE_BYTES = 64 * 1024     # a line longer than this is treated as damage


class AuditError(Exception):
    pass


def _clean(value: Any, depth: int = 0) -> Any:
    """Make a detail value JSON-safe, bounded and free of control characters."""
    if depth > 4:
        return "…"
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        return {str(k)[:80]: _clean(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple, set)):
        return [_clean(v, depth + 1) for v in list(value)[:40]]
    text = "".join(c if c.isprintable() else "?" for c in str(value))
    return text[:_MAX_DETAIL_CHARS]


def _digest(prev: str, body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((prev + "\n" + canonical).encode("utf-8")).hexdigest()


def _actor() -> dict[str, Any]:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry / no env on odd systems
        user = "unknown"
    return {"user": user, "host": platform.node() or "unknown", "pid": os.getpid()}


class AuditLog:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.dir = self.config.data_dir / "audit"
        self.path = self.dir / "audit.jsonl"
        self._lock = self.dir / "audit.lock"

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.config, "audit_log", True))

    # -- writing ----------------------------------------------------------
    def record(self, event: str, **details: Any) -> dict[str, Any] | None:
        """Append one entry. Best-effort by design: an unwritable audit log must
        never stop a scan or strand a quarantine half-done. A failed write is
        reported on stderr once and shows up as a gap to ``audit verify``."""
        if not self.enabled:
            return None
        try:
            return self._append(event, details)
        except Exception as exc:  # noqa: BLE001
            _warn_once(f"warden: could not write the audit log ({exc})")
            return None

    def _append(self, event: str, details: dict[str, Any]) -> dict[str, Any]:
        secure_dir(self.dir)
        with file_lock(self._lock):
            seq, prev = self._tail()
            body: dict[str, Any] = {
                "seq": seq + 1, "ts": now_iso(), "event": str(event)[:80],
                "actor": _actor(), "details": _clean(details), "prev": prev,
            }
            entry = {**body, "hash": _digest(prev, body)}
            line = json.dumps(entry, separators=(",", ":"), ensure_ascii=True) + "\n"
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            if seq == 0:
                fsync_dir(self.dir)
            return entry

    def _tail(self) -> tuple[int, str]:
        """(seq, hash) of the last well-formed entry; (0, GENESIS) if none."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return 0, GENESIS
        if size == 0:
            return 0, GENESIS
        with open(self.path, "rb") as fh:
            fh.seek(max(0, size - _MAX_LINE_BYTES * 2))
            chunk = fh.read()
        for raw in reversed(chunk.splitlines()):
            try:
                entry = json.loads(raw.decode("utf-8"))
                return int(entry["seq"]), str(entry["hash"])
            except (ValueError, KeyError, TypeError, UnicodeDecodeError):
                continue
        # The tail is unreadable: keep appending (never lose new events), but
        # chain from a marker so verify() pinpoints the damage.
        return 0, hashlib.sha256(b"warden-audit-damaged-tail").hexdigest()

    # -- reading ----------------------------------------------------------
    def _lines(self) -> Iterator[tuple[int, bytes]]:
        try:
            with open(self.path, "rb") as fh:
                for number, raw in enumerate(fh, start=1):
                    yield number, raw.rstrip(b"\r\n")
        except FileNotFoundError:
            return

    def entries(self, *, limit: int | None = None, event: str | None = None,
                since_days: float | None = None) -> list[dict[str, Any]]:
        """Entries, oldest first (the last ``limit`` after filtering)."""
        cutoff = None if since_days is None else time.time() - since_days * 86400
        out: list[dict[str, Any]] = []
        for _, raw in self._lines():
            try:
                entry = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(entry, dict):
                continue
            if event and not str(entry.get("event", "")).startswith(event):
                continue
            if cutoff is not None and (_epoch(entry.get("ts")) or 0) < cutoff:
                continue
            out.append(entry)
        return out[-limit:] if limit else out

    def verify(self) -> dict[str, Any]:
        """Re-walk the hash chain. Returns a summary dict with ``ok``."""
        prev = GENESIS
        also_ok: str | None = None      # a second acceptable ``prev`` right after a prune anchor
        count = 0
        last_seq = 0
        problems: list[str] = []
        first_ts = last_ts = None
        for number, raw in self._lines():
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw.decode("utf-8"))
                body = {k: entry[k] for k in ("seq", "ts", "event", "actor", "details", "prev")}
                claimed = entry["hash"]
            except (ValueError, KeyError, TypeError, UnicodeDecodeError):
                problems.append(f"line {number}: not a valid audit entry")
                prev = "invalid"
                continue
            anchor = entry["event"] == "audit.pruned" and count == 0
            if anchor:
                # A pruned log starts from an anchor that names the hash it
                # continues from; accept it as the new start of the chain.
                prev = str(body["prev"])
            if body["prev"] != prev and body["prev"] != also_ok:
                problems.append(f"line {number} (seq {body['seq']}): does not follow the previous entry "
                                f"(entries removed, reordered or inserted)")
            if _digest(str(body["prev"]), body) != claimed:
                problems.append(f"line {number} (seq {body['seq']}): content does not match its hash "
                                f"(entry was modified)")
            if count and isinstance(body["seq"], int) and body["seq"] != last_seq + 1:
                problems.append(f"line {number}: sequence jumps from {last_seq} to {body['seq']}")
            last_seq = body["seq"] if isinstance(body["seq"], int) else last_seq
            # Entries kept by a prune still point at the removed entry's hash;
            # entries written after it point at the anchor. Both are valid
            # successors of an anchor - and of nothing else.
            also_ok = str(body["prev"]) if anchor else None
            prev = str(claimed)
            count += 1
            first_ts = first_ts or body["ts"]
            last_ts = body["ts"]
            if len(problems) >= 20:
                problems.append("…further problems not listed")
                break
        return {
            "ok": not problems, "entries": count, "head_hash": prev if count else None,
            "first": first_ts, "last": last_ts, "problems": problems, "path": str(self.path),
            "enabled": self.enabled,
        }

    # -- maintenance ------------------------------------------------------
    def export(self, out_path: Path) -> dict[str, Any]:
        """Copy the log to ``out_path`` (refusing to overwrite) and return the
        verification summary of what was exported."""
        out_path = Path(out_path)
        if out_path.exists():
            raise AuditError(f"{out_path} already exists; refusing to overwrite")
        summary = self.verify()
        with file_lock(self._lock):
            try:
                data = self.path.read_bytes()
            except FileNotFoundError:
                data = b""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.record("audit.export", path=str(out_path), entries=summary["entries"],
                    head_hash=summary["head_hash"])
        return summary

    def prune(self, older_than_days: float) -> int:
        """Drop entries older than ``older_than_days``; returns how many.

        The remaining log starts with an ``audit.pruned`` anchor that records
        the hash of the last removed entry, so the chain stays verifiable and
        the removal itself is on the record.
        """
        if older_than_days < 0:
            raise AuditError("age must not be negative")
        cutoff = time.time() - older_than_days * 86400
        secure_dir(self.dir)
        with file_lock(self._lock):
            kept: list[bytes] = []
            removed = 0
            last_removed_hash = GENESIS
            last_removed_seq = 0
            for _, raw in self._lines():
                try:
                    entry = json.loads(raw.decode("utf-8"))
                    when = _epoch(entry.get("ts"))
                except (ValueError, UnicodeDecodeError, AttributeError):
                    entry, when = None, None
                if not kept and entry is not None and when is not None and when < cutoff:
                    removed += 1
                    last_removed_hash = str(entry.get("hash", GENESIS))
                    if isinstance(entry.get("seq"), int):
                        last_removed_seq = entry["seq"]
                else:
                    kept.append(raw)
            if not removed:
                return 0
            # The anchor takes the sequence number of the last entry it replaces,
            # so numbering continues unbroken on either side of it.
            body = {
                "seq": last_removed_seq, "ts": now_iso(), "event": "audit.pruned", "actor": _actor(),
                "details": {"removed_entries": removed, "older_than_days": older_than_days,
                            "continues_from": last_removed_hash},
                "prev": last_removed_hash,
            }
            anchor = {**body, "hash": _digest(last_removed_hash, body)}
            # The first kept entry still names the removed entry as its ``prev``;
            # the anchor carries that same hash, and verify() restarts from it.
            tmp = self.path.with_suffix(".jsonl.tmp")
            with open(tmp, "wb") as fh:
                fh.write(json.dumps(anchor, separators=(",", ":")).encode("utf-8") + b"\n")
                for raw in kept:
                    fh.write(raw + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
            if os.name != "nt":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            fsync_dir(self.dir)
        return removed


def _epoch(ts: Any) -> float | None:
    try:
        dt = datetime.fromisoformat(str(ts))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


_warned: set[str] = set()


def _warn_once(message: str) -> None:
    if message not in _warned:
        _warned.add(message)
        print(message, file=sys.stderr)


def record(event: str, config: Config | None = None, **details: Any) -> None:
    """Module-level convenience used at call sites: ``audit.record("x", cfg, a=1)``."""
    AuditLog(config).record(event, **details)


def scan_details(report: Any, *, kind: str, source: str, history_id: str | None = None,
                 online: bool = False) -> dict[str, Any]:
    """The audit summary of a finished scan/sweep (counts, not per-file paths)."""
    threats = len(report.threats)
    return {
        "kind": kind, "source": source, "target": report.root,
        "files_scanned": report.files_scanned, "threats": threats, "unknown": len(report.unknown),
        "complete": report.coverage_complete, "stopped": report.stopped,
        "outcome": "threats" if threats else ("clean" if report.coverage_complete else "incomplete"),
        "engines": report.engines, "online_lookups": bool(online),
        "duration_seconds": report.duration_seconds, "history_id": history_id,
    }
