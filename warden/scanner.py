"""The scanner: walks targets, runs engines, aggregates results.

This is the core API the CLI, the system sweep, the scheduler, and the GUI all
call. It knows nothing about presentation - it just produces a ``ScanReport``.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from .config import BUNDLED_RULES_DIR, Config
from .engines import (
    ClamAVEngine,
    Engine,
    HashEngine,
    HeuristicsEngine,
    ScanContext,
    YaraEngine,
)
from .models import FileResult, ScanReport, now_iso

# Directory recursion safety limits (defend against symlink cycles / pathological
# trees even when follow_symlinks is on).
_MAX_DEPTH = 100

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
        self._engines: list[Engine] = [self.yara, self.hashes, self.heuristics, self.clamav]

        # An engine that FAILED to load (e.g. a broken YARA ruleset) silently
        # reduces coverage; record it so scans are reported degraded, not clean.
        self.engine_warnings: list[str] = []
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
        report = ScanReport(root=str(target), engines=self.active_engines(),
                            warnings=list(self.engine_warnings))

        for path in self._iter_files(target, recursive=recursive, report=report):
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
        report = ScanReport(root="<file-list>", engines=self.active_engines(),
                            warnings=list(self.engine_warnings))
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
            if skip_ext:
                report.skipped_ext += 1
            elif too_big:
                report.skipped_oversized += 1
        return result


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
    from .models import Finding
    return Finding.engine_error(engine, f"{engine} raised: {exc!r}")
