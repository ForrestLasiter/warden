"""The scanner: walks targets, runs engines, aggregates results.

This is the core API the CLI, the system sweep, the scheduler, and the GUI all
call. It knows nothing about presentation - it just produces a ``ScanReport``.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from .config import Config, BUNDLED_RULES_DIR
from .engines import (
    ClamAVEngine,
    HashEngine,
    HeuristicsEngine,
    ScanContext,
    YaraEngine,
)
from .models import FileResult, ScanReport, now_iso

# Callback fired after each file so UIs can show live progress.
ProgressCallback = Callable[[FileResult], None]


class Scanner:
    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.config.ensure_dirs()

        rule_dirs = [BUNDLED_RULES_DIR, self.config.rules_user_dir]
        reputation = None
        if self.config.online_hash_lookup:
            from .reputation import OnlineReputation
            reputation = OnlineReputation(self.config)
        self.yara = YaraEngine(rule_dirs)
        self.hashes = HashEngine(rule_dirs, reputation=reputation)
        self.heuristics = HeuristicsEngine()
        self.clamav = ClamAVEngine(enabled=self.config.use_clamav)

        # Content engines need file bytes; hash/clam operate differently.
        self._engines = [self.yara, self.hashes, self.heuristics, self.clamav]

    # -- introspection ----------------------------------------------------
    def engine_status(self) -> dict[str, str]:
        return {
            "yara": self.yara.status,
            "hash": self.hashes.status,
            "heuristics": self.heuristics.status,
            "clamav": self.clamav.status,
        }

    def active_engines(self) -> list[str]:
        return [e.name for e in self._engines if e.available()]

    # -- scanning ---------------------------------------------------------
    def scan_path(
        self,
        target: str | Path,
        *,
        recursive: bool = True,
        progress: ProgressCallback | None = None,
    ) -> ScanReport:
        target = Path(target)
        report = ScanReport(root=str(target), engines=self.active_engines())

        for path in self._iter_files(target, recursive=recursive):
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
    ) -> ScanReport:
        """Scan an explicit list of files (used by the system sweep)."""
        report = ScanReport(root="<file-list>", engines=self.active_engines())
        for p in paths:
            path = Path(p)
            if not path.is_file():
                continue
            result = self._scan_file(path, report)
            report.results.append(result)
            if progress:
                progress(result)
        report.finished = now_iso()
        return report

    # -- internals --------------------------------------------------------
    def _iter_files(self, target: Path, *, recursive: bool) -> Iterator[Path]:
        if target.is_file():
            yield target
            return
        if not target.is_dir():
            return
        if not recursive:
            for entry in _safe_scandir(target):
                if entry.is_file(follow_symlinks=self.config.follow_symlinks):
                    yield Path(entry.path)
            return
        # Manual walk so we control symlink following and error handling.
        stack = [target]
        while stack:
            current = stack.pop()
            for entry in _safe_scandir(current):
                try:
                    if entry.is_dir(follow_symlinks=self.config.follow_symlinks):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=self.config.follow_symlinks):
                        yield Path(entry.path)
                except OSError:
                    continue

    def _scan_file(self, path: Path, report: ScanReport) -> FileResult:
        result = FileResult(path=str(path))
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.error = f"stat failed: {exc}"
            report.errors += 1
            return result
        result.size = size

        ext = path.suffix.lower()
        deep = ext not in self.config.skip_extensions and size <= self.config.max_scan_bytes

        ctx = ScanContext(path=path, size=size, max_read=self.config.max_scan_bytes)

        # Hash always runs (cheap, streamed, needed for reputation + records).
        result.sha256 = ctx.sha256()

        for engine in self._engines:
            if not engine.available():
                continue
            # Content engines (yara, heuristics) are gated by the deep flag;
            # hash + clamav still run on skipped-for-content files.
            if engine.name in ("yara", "heuristics") and not deep:
                continue
            try:
                result.findings.extend(engine.scan(ctx))
            except Exception as exc:  # noqa: BLE001 - never let one engine kill the scan
                result.findings.append(_engine_error(engine.name, exc))

        if ctx.read_error and not result.findings:
            result.error = ctx.read_error
            report.errors += 1
            return result

        result.scanned = True
        report.files_scanned += 1
        report.bytes_scanned += size
        if not deep:
            report.files_skipped += 1
        return result


def _safe_scandir(path: Path):
    try:
        with os.scandir(path) as it:
            yield from it
    except OSError:
        return


def _engine_error(engine: str, exc: Exception):
    from .models import Finding
    return Finding.engine_error(engine, f"{engine} raised: {exc!r}")
