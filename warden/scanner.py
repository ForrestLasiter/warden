"""The scanner: walks targets, runs engines, aggregates results.

This is the core API the CLI, the system sweep, the scheduler, and the GUI all
call. It knows nothing about presentation - it just produces a ``ScanReport``.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .archive import ArchiveLimits, ArchiveStats, archive_kind, iter_members
from .config import BUNDLED_RULES_DIR, Config
from .engines import (
    ClamAVEngine,
    DocumentEngine,
    Engine,
    HashEngine,
    HeuristicsEngine,
    ScanContext,
    YaraEngine,
)
from .models import FileResult, Finding, ScanReport, Severity, now_iso

# Directory recursion safety limits (defend against symlink cycles / pathological
# trees even when follow_symlinks is on).
_MAX_DEPTH = 100

# Engines that read file content (as opposed to hashing it or handing the path
# to an external tool). Gated by the size/extension "deep scan" decision, and
# the only engines that run on in-memory archive members.
_CONTENT_ENGINES = ("yara", "heuristics", "documents")
_MAX_MEMBER_NAME = 200

# Callback fired after each file so UIs can show live progress.
ProgressCallback = Callable[[FileResult], None]


@dataclass(slots=True)
class ScanLimits:
    """Ways a scan can be told to stop early. A stopped scan is reported as
    incomplete - it is never mistaken for a clean one."""
    cancel: Callable[[], bool] | None = None    # polled between files
    timeout: float | None = None                # seconds of wall-clock time
    max_files: int | None = None                # files examined
    _deadline: float | None = None

    def start(self) -> None:
        self._deadline = time.monotonic() + self.timeout if self.timeout else None

    def reason(self, files_done: int) -> str | None:
        if self.cancel is not None and self.cancel():
            return "cancelled"
        if self._deadline is not None and time.monotonic() >= self._deadline:
            return "time limit reached"
        if self.max_files is not None and files_done >= self.max_files:
            return "file limit reached"
        return None


class Scanner:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.config.ensure_dirs()

        rule_dirs = [BUNDLED_RULES_DIR, self.config.rules_user_dir]
        # Installed rule packs: only those whose files still match their
        # manifest are loaded; a tampered pack becomes an engine warning.
        from .rulepacks import RulePackManager
        pack_dirs, pack_warnings = RulePackManager(self.config).active_dirs()
        rule_dirs += pack_dirs
        reputation = None
        self.advisories: list[str] = []
        if self.config.online_hash_lookup:
            from . import net
            if net.is_offline(self.config):
                self.advisories.append(
                    "offline mode is on: online hash reputation was requested but not used")
            else:
                from .reputation import OnlineReputation
                reputation = OnlineReputation(self.config)
        self.yara = YaraEngine(rule_dirs)
        self.hashes = HashEngine(rule_dirs, reputation=reputation)
        self.heuristics = HeuristicsEngine()
        self.documents = DocumentEngine()
        self.clamav = ClamAVEngine(enabled=self.config.use_clamav)
        self.archive_limits = ArchiveLimits()

        # Content engines need file bytes; hash/clam operate differently.
        self._engines: list[Engine] = [
            self.yara, self.hashes, self.heuristics, self.documents, self.clamav]

        stale = self.clamav.freshness_advisory()
        if stale:
            self.advisories.append(stale)

        # An engine that FAILED to load (e.g. a broken YARA ruleset) silently
        # reduces coverage; record it so scans are reported degraded, not clean.
        self.engine_warnings: list[str] = list(pack_warnings)
        for e in self._engines:
            load_error = getattr(e, "load_error", None)
            if load_error:
                self.engine_warnings.append(f"{e.name}: {load_error}")

    # -- introspection ----------------------------------------------------
    def engine_status(self) -> dict[str, str]:
        return {
            "yara": self.yara.status,
            "hash": self.hashes.status,
            "heuristics": self.heuristics.status,
            "documents": self.documents.status,
            "clamav": self.clamav.status,
        }

    def active_engines(self) -> list[str]:
        return [e.name for e in self._engines if e.available()]

    def inactive_engines(self) -> dict[str, str]:
        """Engines that will not take part in a scan, and why."""
        status = self.engine_status()
        return {e.name: status.get(e.name, "inactive")
                for e in self._engines if not e.available()}

    # -- scanning ---------------------------------------------------------
    def scan_path(
        self,
        target: str | Path,
        *,
        recursive: bool = True,
        progress: ProgressCallback | None = None,
        limits: ScanLimits | None = None,
    ) -> ScanReport:
        target = Path(target)
        report = ScanReport(root=str(target), engines=self.active_engines(),
                            inactive_engines=self.inactive_engines(),
                            warnings=list(self.engine_warnings),
                            advisories=list(self.advisories))

        if limits:
            limits.start()
        for path in self._iter_files(target, recursive=recursive, report=report):
            if limits:
                report.stopped = limits.reason(len(report.results))
                if report.stopped:
                    break
            result = self._scan_file(path, report)
            report.results.append(result)
            if progress:
                progress(result)

        report.finished = now_iso()
        return report

    def scan_files(
        self,
        paths: Iterable[str | Path],
        *,
        progress: ProgressCallback | None = None,
        limits: ScanLimits | None = None,
    ) -> ScanReport:
        """Scan an explicit list of files (used by the system sweep)."""
        report = ScanReport(root="<file-list>", engines=self.active_engines(),
                            inactive_engines=self.inactive_engines(),
                            warnings=list(self.engine_warnings),
                            advisories=list(self.advisories))
        if limits:
            limits.start()
        for p in paths:
            if limits:
                report.stopped = limits.reason(len(report.results))
                if report.stopped:
                    break
            path = Path(p)
            if not path.is_file():
                continue
            result = self._scan_file(path, report)
            report.results.append(result)
            if progress:
                progress(result)
        report.finished = now_iso()
        return report

    def scan_bytes(self, name: str, data: bytes) -> FileResult:
        """Scan content that is already in memory (never touches the disk).

        Used to re-check a quarantined item against today's rules before it is
        restored. Runs the content engines, the local hash denylist and the
        archive walk; skips engines that need a real file path.
        """
        ctx = ScanContext.from_bytes(name, data)
        result = FileResult(path=str(name), size=len(data), sha256=ctx.sha256(), scanned=True)
        self._run_engines(ctx, result, deep=True)
        self._inspect_content(ctx, result, None)
        return result

    # -- internals --------------------------------------------------------
    def _iter_files(self, target: Path, *, recursive: bool, report: ScanReport) -> Iterator[Path]:
        follow = self.config.follow_symlinks
        try:
            is_link = target.is_symlink()
        except OSError:
            is_link = False

        if target.is_file():
            if is_link and not follow:
                report.unreadable.append(f"{target} (symlink; follow_symlinks is off)")
                return
            yield target
            return
        if not target.is_dir():
            if target.exists():
                report.unreadable.append(str(target))
            return
        if is_link and not follow:
            report.unreadable.append(f"{target} (symlinked directory; follow_symlinks is off)")
            return

        if not recursive:
            for entry in _scandir_or_record(target, report):
                try:
                    if entry.is_file(follow_symlinks=follow):
                        yield Path(entry.path)
                except OSError:
                    report.unreadable.append(entry.path)
            return

        # Manual walk with a cycle guard (visited dir identities) and depth limit.
        visited: set = set()
        stack: list[tuple[Path, int]] = [(target, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > _MAX_DEPTH:
                report.unreadable.append(f"{current} (max depth {_MAX_DEPTH} reached)")
                continue
            key = _dir_identity(current)
            if key is not None:
                if key in visited:
                    continue  # symlink/junction cycle - already walked this dir
                visited.add(key)
            for entry in _scandir_or_record(current, report):
                try:
                    if entry.is_dir(follow_symlinks=follow):
                        stack.append((Path(entry.path), depth + 1))
                    elif entry.is_file(follow_symlinks=follow):
                        yield Path(entry.path)
                except OSError:
                    report.unreadable.append(entry.path)
                    continue

    def _scan_file(self, path: Path, report: ScanReport) -> FileResult:
        result = FileResult(path=str(path))
        # Reject an explicitly-supplied symlink file when not following symlinks
        # (covers the system sweep, which passes paths straight to _scan_file).
        if not self.config.follow_symlinks:
            try:
                if path.is_symlink():
                    result.error = "symlink skipped (follow_symlinks is off)"
                    report.unreadable.append(f"{path} (symlink)")
                    report.errors += 1
                    return result
            except OSError:
                pass
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.error = f"stat failed: {exc}"
            report.errors += 1
            return result
        result.size = size

        ext = path.suffix.lower()
        skip_ext = ext in self.config.skip_extensions
        too_big = size > self.config.max_scan_bytes
        deep = not skip_ext and not too_big

        ctx = ScanContext(path=path, size=size, max_read=self.config.max_scan_bytes)

        # Hash everything except skip-listed types (media/VM images). Hashing a
        # 50 GB .vmdk we're not content-scanning would read every byte for a
        # reputation lookup that never runs on it. Executables/scripts (the
        # reputation candidates) are never on the skip list, so they're hashed.
        if not skip_ext:
            result.sha256 = ctx.sha256()

        self._run_engines(ctx, result, deep=deep)

        if ctx.read_error and not result.findings:
            result.error = ctx.read_error
            report.errors += 1
            return result

        if deep:
            self._inspect_content(ctx, result, report)
        if result.is_threat and self.config.check_signatures:
            self._attach_signature(path, result)

        result.scanned = True
        report.files_scanned += 1
        report.bytes_scanned += size
        if not deep:
            report.files_skipped += 1
            if skip_ext:
                report.skipped_ext += 1
            elif too_big:
                report.skipped_oversized += 1
        return result


    def _run_engines(self, ctx: ScanContext, result: FileResult, *, deep: bool,
                     only: tuple[str, ...] | None = None,
                     tag: str | None = None) -> None:
        """Run every applicable engine over one context, into ``result``.

        ``tag`` marks findings as coming from an archive member (so a report
        reader can see *which* file inside the container was flagged).
        """
        for engine in self._engines:
            if not engine.available():
                continue
            if only is not None and engine.name not in only:
                continue
            # Content engines are gated by the deep flag; hash + clamav still
            # run on skipped-for-content files.
            if engine.name in _CONTENT_ENGINES and not deep:
                continue
            try:
                found = engine.scan(ctx)
            except Exception as exc:  # noqa: BLE001 - never let one engine kill the scan
                found = [_engine_error(engine.name, exc)]
            if tag:
                for f in found:
                    f.meta["archive_member"] = tag
                    f.description = f"{f.description} [inside {tag}]"
            result.findings.extend(found)

    def _inspect_content(self, ctx: ScanContext, result: FileResult,
                         report: ScanReport | None) -> None:
        """Post-engine context: executable metadata and the archive walk."""
        info = ctx.cache.get("binary")
        if info:
            result.meta["binary"] = {k: v for k, v in info.items() if k != "observations"}

        if not self.config.scan_archives:
            return
        data = ctx.data()
        if archive_kind(data) is None:
            return
        stats = ArchiveStats()
        self._scan_archive(data, ctx.path.name, result, stats, depth=1)
        result.meta["archive"] = {
            "members_scanned": stats.members_scanned,
            "members_skipped": stats.members_skipped,
            "encrypted_members": stats.encrypted,
            "complete": not stats.truncated and not stats.members_skipped,
            "notes": stats.reasons,
        }
        if report is not None:
            report.archives_opened += 1
            report.archive_members_scanned += stats.members_scanned
            report.archive_members_skipped += stats.members_skipped
        if stats.bomb:
            result.findings.append(Finding(
                engine="archive", name="archive-bomb-suspected", severity=Severity.MEDIUM,
                description="Archive expands far beyond its size (possible decompression bomb); "
                            "its contents were not fully inspected",
                meta={"notes": stats.reasons}))
        if stats.encrypted:
            result.findings.append(Finding(
                engine="archive", name="encrypted-archive-member", severity=Severity.LOW,
                description=f"{stats.encrypted} password-protected member(s) could not be inspected "
                            f"(a common way to slip malware past scanners)",
                meta={"encrypted_members": stats.encrypted}))
        if stats.truncated and not stats.bomb:
            result.findings.append(Finding(
                engine="archive", name="archive-partially-scanned", severity=Severity.INFO,
                description="Archive was only partly inspected: " + "; ".join(stats.reasons[:4]),
                meta={"notes": stats.reasons}))

    def _scan_archive(self, data: bytes, label: str, result: FileResult,
                      stats: ArchiveStats, *, depth: int) -> None:
        limits = self.archive_limits
        # An Office (OOXML) container is examined as a whole by the documents
        # engine; running it again on each part would only duplicate findings.
        ooxml = b"[Content_Types].xml" in data
        only = tuple(e for e in (*_CONTENT_ENGINES, "hash") if not (ooxml and e == "documents"))
        for member, blob in iter_members(data, label, limits, stats):
            stats.members_scanned += 1
            shown = _clean_member_name(member)
            tag = f"{label}!/{shown}"
            mctx = ScanContext.from_bytes(shown or "member", blob)
            self._run_engines(mctx, result, deep=True, only=only, tag=tag)
            if archive_kind(blob) is not None:
                if depth >= limits.max_depth:
                    stats.truncated = True
                    stats.members_skipped += 1
                    stats.note(f"nesting deeper than {limits.max_depth} levels not opened")
                else:
                    self._scan_archive(blob, tag, result, stats, depth=depth + 1)
            if stats.bomb or stats.total_bytes > limits.max_total_bytes:
                return

    def _attach_signature(self, path: Path, result: FileResult) -> None:
        """Add the OS code-signature verdict to a flagged executable (context
        for the reader - it never changes the verdict)."""
        binary = result.meta.get("binary") or {}
        if binary.get("format") not in ("pe", "macho"):
            return
        from .signature import signature_info
        result.meta["signature"] = signature_info(path)


def _clean_member_name(name: str) -> str:
    """An archive member name is attacker-controlled text that ends up in
    reports and on terminals: drop control characters and bound the length."""
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in str(name))
    return cleaned[:_MAX_MEMBER_NAME]


def _scandir_or_record(path: Path, report: ScanReport):
    """os.scandir, recording the directory as unreadable instead of silently
    swallowing the error (so the scan can report incomplete coverage)."""
    try:
        with os.scandir(path) as it:
            yield from it
    except OSError as exc:
        report.unreadable.append(f"{path} ({exc.strerror or exc})")
        return


def _dir_identity(path: Path):
    """A stable identity for a directory for cycle detection. Uses (device, inode)
    where available, else the resolved path string."""
    try:
        st = path.stat()
        if st.st_ino:
            return (st.st_dev, st.st_ino)
    except OSError:
        return None
    try:
        return str(path.resolve())
    except OSError:
        return None


def _engine_error(engine: str, exc: Exception):
    return Finding.engine_error(engine, f"{engine} raised: {exc!r}")
