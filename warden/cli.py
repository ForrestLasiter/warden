"""Warden command-line interface.

    warden status                 show which engines are active
    warden scan <path>            scan a file or folder on demand
    warden scan <path> --quarantine   isolate anything flagged (asks first)
    warden quarantine list        show quarantined items
    warden quarantine restore ID  put a file back
    warden quarantine delete ID   permanently remove (confirms)
    warden update-rules           info on adding rules/signatures
"""

from __future__ import annotations

import contextlib
import json as _json
import signal
import sys
import threading
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape as _rich_escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__, audit, net
from .config import Config
from .history import History
from .models import FileResult, ScanReport, Severity
from .quarantine import Quarantine, QuarantineError
from .scanner import ScanLimits, Scanner
from .scheduler import Scheduler, SchedulerError, ScheduleSpec
from .sweep import SystemSweep

app = typer.Typer(
    add_completion=False,
    help="Warden - open-source malware scanner (YARA + heuristics + hashes + optional ClamAV).",
    no_args_is_help=True,
)
quarantine_app = typer.Typer(help="Manage quarantined files.", no_args_is_help=True)
app.add_typer(quarantine_app, name="quarantine")
history_app = typer.Typer(help="Review past scan/sweep reports.", no_args_is_help=True)
app.add_typer(history_app, name="history")
schedule_app = typer.Typer(help="Schedule recurring scans via the OS scheduler.", no_args_is_help=True)
app.add_typer(schedule_app, name="schedule")
config_app = typer.Typer(help="View and change Warden settings (~/.warden/config.json).", no_args_is_help=True)
app.add_typer(config_app, name="config")
rules_app = typer.Typer(help="Install, verify and roll back signed rule packs.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")
audit_app = typer.Typer(help="Review and verify the audit trail of what Warden did.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")

def _harden_stdio() -> None:
    """Never let an un-encodable character crash a command.

    Output does not always go to a UTF-8 terminal: it may be redirected to NUL
    or a file, captured by a scheduler, or shown in a console using a legacy
    code page (cp1252, cp437). File names can contain any character. With
    ``errors="replace"`` such a character is printed as '?' instead of raising
    UnicodeEncodeError half-way through a scan.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")      # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def _spinner_name(encoding: str | None = None) -> str:
    """Rich's default spinner is drawn with braille characters, which only
    exist in Unicode encodings; fall back to an ASCII one elsewhere."""
    enc = (encoding if encoding is not None else getattr(sys.stdout, "encoding", "") or "")
    return "dots" if enc.lower().replace("-", "").replace("_", "") in ("utf8", "utf8sig") else "line"


_harden_stdio()
console = Console()

_SEV_STYLE = {
    Severity.CLEAN: "green",
    Severity.INFO: "cyan",
    Severity.LOW: "yellow",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold white on red",
}


def _style(sev: Severity) -> str:
    return _SEV_STYLE.get(sev, "white")


def _esc(value: object) -> str:
    """Make untrusted text (file names, archive member names, rule metadata)
    safe to print: neutralize Rich markup and drop control characters, so a
    crafted name can neither crash the renderer nor inject terminal escapes."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return _rich_escape(text)


@app.callback()
def _global_options(
    offline: bool = typer.Option(
        False, "--offline",
        help="Never use the network, whatever else is configured (also: WARDEN_OFFLINE=1)."),
):
    """Warden - open-source malware scanner (YARA + heuristics + hashes + optional ClamAV)."""
    net.set_offline(offline)


@app.command()
def version():
    """Print the Warden version."""
    console.print(f"Warden {__version__}")


@app.command()
def status():
    """Show which detection engines are active and how they're configured."""
    scanner = Scanner()
    cfg = scanner.config
    table = Table(title="Warden engine status", show_lines=False)
    table.add_column("Engine", style="bold")
    table.add_column("State")
    table.add_column("Detail")
    for name, detail in scanner.engine_status().items():
        active = name in scanner.active_engines()
        state = "[green]active[/]" if active else "[dim]inactive[/]"
        table.add_row(name, state, detail)
    console.print(table)
    console.print(f"[dim]Data dir:[/] {cfg.data_dir}")
    console.print(f"[dim]Quarantine:[/] {cfg.quarantine_dir}")
    console.print(f"[dim]User rules:[/] {cfg.rules_user_dir}  (drop .yar files or malware_hashes.txt here)")
    console.print(f"[dim]Network:[/] {_network_summary(cfg)}")
    for note in scanner.advisories:
        console.print(f"[yellow]note:[/] {_esc(note)}")
    if not scanner.clamav.available():
        console.print("[dim]Tip: install ClamAV + run freshclam for millions more signatures (optional).[/]")


def _network_summary(cfg: Config) -> str:
    if net.is_offline(cfg):
        return "offline mode - no network access"
    if cfg.online_hash_lookup:
        return "online hash reputation ENABLED (file hashes are sent to the reputation provider)"
    return "none (online hash reputation is off)"


@app.command()
def scan(
    path: str = typer.Argument(..., help="File or folder to scan."),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", "-r", help="Recurse into subfolders."),
    quarantine: bool = typer.Option(False, "--quarantine", "-q", help="Offer to isolate flagged files."),
    min_severity: str = typer.Option("low", "--min-severity", help="Only report findings at/above this level (clean/info/low/medium/high/critical)."),
    json_out: str | None = typer.Option(None, "--json", help="Write full report as JSON to this path."),
    quiet: bool = typer.Option(False, "--quiet", help="Only print the summary and threats."),
    save: bool = typer.Option(False, "--save", help="Save this report to scan history (~/.warden/history)."),
    online: bool = typer.Option(False, "--online", help="Also check file hashes against online reputation (opt-in)."),
    archives: bool = typer.Option(True, "--archives/--no-archives", help="Look inside zip/tar/gzip archives (bounded)."),
    timeout: float = typer.Option(0, "--timeout", min=0, help="Stop after this many seconds (0 = no limit). A stopped scan exits 2."),
    max_files: int = typer.Option(0, "--max-files", min=0, help="Stop after this many files (0 = no limit)."),
):
    """Scan a file or folder for malware on demand."""
    target = Path(path)
    if not target.exists():
        console.print(f"[red]Path not found:[/] {target}")
        raise typer.Exit(2)

    try:
        threshold = Severity.parse(min_severity)
    except (KeyError, ValueError):
        console.print(f"[red]Invalid --min-severity:[/] {min_severity}")
        raise typer.Exit(2)

    cfg = Config.load()
    if online:
        cfg.online_hash_lookup = True
    if not archives:
        cfg.scan_archives = False
    scanner = Scanner(cfg)
    console.print(Panel.fit(
        f"[bold]Warden[/] scanning [cyan]{_esc(target)}[/]\n"
        f"engines: {', '.join(scanner.active_engines()) or 'none!'}",
        border_style="blue",
    ))

    threats: list[FileResult] = []

    with Progress(
        SpinnerColumn(spinner_name=_spinner_name()),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.fields[count]} files"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("scanning", total=None, count=0)
        count = 0

        def on_file(result: FileResult):
            nonlocal count
            count += 1
            progress.update(task, count=count, description=f"scanning {_esc(Path(result.path).name[:40])}")
            if result.is_threat:
                threats.append(result)

        with _interruptible() as interrupted:
            report = scanner.scan_path(
                target, recursive=recursive, progress=on_file,
                limits=ScanLimits(cancel=interrupted.is_set, timeout=timeout or None,
                                  max_files=max_files or None))

    _print_report(report, threshold=threshold, quiet=quiet)

    if json_out:
        Path(json_out).write_text(_json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]JSON report written to {json_out}[/]")

    history_id = None
    if save:
        entry = History().save(report, kind="scan")
        history_id = entry.id
        console.print(f"[dim]Saved to history as {entry.id}[/]")
    audit.record("scan.completed", cfg, exit_code=_scan_exit_code(report),
                 **audit.scan_details(report, kind="scan", source="cli", history_id=history_id,
                                      online=cfg.online_hash_lookup and not net.is_offline(cfg)))

    if quarantine and threats:
        _do_quarantine(threats)

    raise typer.Exit(_scan_exit_code(report))


@app.command()
def sweep(
    quick: bool = typer.Option(False, "--quick", help="Faster: top-level temp/downloads + executables only."),
    quarantine: bool = typer.Option(False, "--quarantine", "-q", help="Offer to isolate flagged files."),
    min_severity: str = typer.Option("low", "--min-severity", help="Only report findings at/above this level."),
    json_out: str | None = typer.Option(None, "--json", help="Write full report as JSON to this path."),
    save: bool = typer.Option(False, "--save", help="Save this report to scan history (~/.warden/history)."),
    online: bool = typer.Option(False, "--online", help="Also check file hashes against online reputation (opt-in)."),
    timeout: float = typer.Option(0, "--timeout", min=0, help="Stop after this many seconds (0 = no limit). A stopped sweep exits 2."),
):
    """Sweep the high-value spots malware hides: autoruns, processes, tasks, Temp, Downloads."""
    try:
        threshold = Severity.parse(min_severity)
    except (KeyError, ValueError):
        console.print(f"[red]Invalid --min-severity:[/] {min_severity}")
        raise typer.Exit(2)

    cfg = Config.load()
    if online:
        cfg.online_hash_lookup = True
    sweeper = SystemSweep(cfg)
    console.print(Panel.fit(
        f"[bold]Warden[/] system sweep{' (quick)' if quick else ''}\n"
        f"engines: {', '.join(sweeper.scanner.active_engines()) or 'none!'}\n"
        f"[dim]gathering autoruns, processes, scheduled tasks, Temp, Downloads...[/]",
        border_style="blue",
    ))

    threats: list[FileResult] = []
    with Progress(
        SpinnerColumn(spinner_name=_spinner_name()),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.fields[count]} files"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("sweeping", total=None, count=0)
        count = 0

        def on_file(result: FileResult):
            nonlocal count
            count += 1
            progress.update(task, count=count, description=f"scanning {_esc(Path(result.path).name[:40])}")
            if result.is_threat:
                threats.append(result)

        with _interruptible() as interrupted:
            report, categories = sweeper.run(
                quick=quick, progress=on_file,
                limits=ScanLimits(cancel=interrupted.is_set, timeout=timeout or None))

    # Category summary
    cat_table = Table(title="Swept locations", show_header=True)
    cat_table.add_column("Category", style="bold")
    cat_table.add_column("Files", justify="right")
    cat_table.add_column("What")
    for c in categories:
        cat_table.add_row(c.name, str(len(c.paths)), c.description)
    console.print(cat_table)

    _print_report(report, threshold=threshold, quiet=False)

    if json_out:
        Path(json_out).write_text(_json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]JSON report written to {json_out}[/]")

    history_id = None
    if save:
        entry = History().save(report, kind="sweep")
        history_id = entry.id
        console.print(f"[dim]Saved to history as {entry.id}[/]")
    audit.record("sweep.completed", cfg, exit_code=_scan_exit_code(report),
                 **audit.scan_details(report, kind="sweep", source="cli", history_id=history_id,
                                      online=cfg.online_hash_lookup and not net.is_offline(cfg)))

    # Recompute threats from the report (location heuristic may have added some).
    flagged = [r for r in report.results if r.is_threat]
    if quarantine and flagged:
        _do_quarantine(flagged)

    raise typer.Exit(_scan_exit_code(report))


@contextlib.contextmanager
def _interruptible():
    """Turn the first Ctrl+C into a graceful stop: the scan finishes the file
    it is on and reports what it covered (as incomplete). A second Ctrl+C
    aborts immediately."""
    flag = threading.Event()
    previous = None

    def handler(signum, frame):
        if flag.is_set():
            raise KeyboardInterrupt
        flag.set()
        console.print("[yellow]Stopping after the current file… (Ctrl+C again to abort)[/]")

    try:
        previous = signal.signal(signal.SIGINT, handler)
    except (ValueError, OSError):       # not the main thread (tests, embedding)
        previous = None
    try:
        yield flag
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


def _print_report(report: ScanReport, *, threshold: Severity, quiet: bool):
    shown = 0
    for r in report.results:
        if r.error:
            if not quiet:
                console.print(f"[dim]! {_esc(Path(r.path).name)}: {_esc(r.error)}[/]")
            continue
        if r.verdict < threshold or not r.findings:
            continue
        shown += 1
        header = f"[{_style(r.verdict)}] {r.verdict.label:8}[/] {_esc(r.path)}"
        console.print(header)
        for f in r.findings:
            if f.severity < threshold:
                continue
            console.print(f"    [{_style(f.severity)}]-[/] ({_esc(f.engine)}) [bold]{_esc(f.name)}[/]: {_esc(f.description)}")
        _print_context(r)

    for note in report.advisories:
        console.print(f"[yellow]note:[/] {_esc(note)}")

    # A degraded scan (e.g. a YARA ruleset that failed to compile) is not "clean".
    for w in report.warnings:
        console.print(f"[yellow]! engine unavailable:[/] {_esc(w)} [dim](coverage reduced)[/]")

    # Surface files an engine could not finish on - these are 'unknown', NOT clean.
    unknown = report.unknown
    if unknown and not quiet:
        for r in unknown:
            console.print(f"[yellow]? UNKNOWN [/] {_esc(r.path)} [dim](an engine could not scan this file)[/]")

    # Coverage gaps: paths we couldn't read at all.
    if report.unreadable and not quiet:
        shown_u = report.unreadable[:15]
        for p in shown_u:
            console.print(f"[yellow]! unreadable:[/] {_esc(p)}")
        if len(report.unreadable) > len(shown_u):
            console.print(f"[dim]  …and {len(report.unreadable) - len(shown_u)} more unreadable path(s)[/]")

    dur = report.duration_seconds or 0.0
    summary = Table.grid(padding=(0, 2))
    summary.add_row("Files scanned:", str(report.files_scanned))
    summary.add_row("Engines used:", _esc(", ".join(report.engines) or "none"))
    if report.inactive_engines:
        summary.add_row("Engines not used:", "[dim]" + _esc("; ".join(
            f"{name} ({why})" for name, why in report.inactive_engines.items())) + "[/]")
    summary.add_row("Skipped by type:", str(report.skipped_ext))
    summary.add_row("Skipped (too large):", str(report.skipped_oversized))
    if report.archives_opened:
        skipped = report.archive_members_skipped
        summary.add_row(
            "Archives opened:",
            f"{report.archives_opened} ({report.archive_members_scanned} member(s) scanned"
            + (f", [yellow]{skipped} not inspected[/]" if skipped else "") + ")")
    summary.add_row("Threats (medium+):", f"[red]{len(report.threats)}[/]" if report.threats else "0")
    summary.add_row("Unknown (engine error):", f"[yellow]{len(unknown)}[/]" if unknown else "0")
    summary.add_row("Unreadable paths:", f"[yellow]{len(report.unreadable)}[/]" if report.unreadable else "0")
    summary.add_row("Findings shown:", str(shown))
    summary.add_row("Read/access errors:", str(report.errors))
    summary.add_row("Duration:", f"{dur:.1f}s")
    if report.threats:
        verdict_color, title = "red", "THREATS FOUND"
    elif report.stopped:
        verdict_color, title = "yellow", f"INCOMPLETE — STOPPED ({report.stopped.upper()})"
    elif not report.coverage_complete:
        verdict_color, title = "yellow", "INCOMPLETE — COVERAGE GAPS"
    else:
        verdict_color, title = "green", "CLEAN"
    console.print(Panel(summary, title=f"[{verdict_color}]{title}[/]", border_style=verdict_color))


def _print_context(r: FileResult) -> None:
    """Non-detection context for a flagged file: what it is and who signed it."""
    from .signature import describe

    binary = r.meta.get("binary")
    if binary:
        bits = [str(binary.get("format", "?")).upper(), str(binary.get("arch", "?")),
                str(binary.get("type", ""))]
        console.print(f"    [dim]file type: {_esc(' '.join(b for b in bits if b))}[/]")
    sig = r.meta.get("signature")
    if sig:
        style = {"valid": "green", "invalid": "red", "untrusted": "yellow"}.get(sig.get("status", ""), "dim")
        console.print(f"    [{style}]signature: {_esc(describe(sig))}[/]")
    elif binary and binary.get("format") in ("pe", "macho"):
        embedded = "present, not verified" if binary.get("signature_embedded") else "none embedded"
        console.print(f"    [dim]signature: {embedded}[/]")


def _scan_exit_code(report: ScanReport) -> int:
    """0 = clean, 1 = threat(s) found, 2 = scan could not be completed fully."""
    if report.threats:
        return 1
    if not report.coverage_complete:
        return 2
    return 0


def _do_quarantine(threats: list[FileResult]):
    console.print(f"\n[yellow]{len(threats)} file(s) flagged.[/] Quarantine isolates them (reversible) and removes the original.")
    for r in threats:
        console.print(f"  [{_style(r.verdict)}]{r.verdict.label}[/] {_esc(r.path)}")
    if not typer.confirm("Quarantine all flagged files now?", default=False):
        console.print("[dim]Skipped quarantine.[/]")
        return
    q = Quarantine()
    for r in threats:
        try:
            entry = q.quarantine_file(r)
            console.print(f"  [green]quarantined[/] {_esc(r.path)}  (id {entry.id})")
        except QuarantineError as exc:
            console.print(f"  [red]failed[/] {_esc(r.path)}: {_esc(exc)}")


# -- quarantine subcommands ----------------------------------------------
@quarantine_app.command("list")
def quarantine_list():
    """List quarantined files."""
    q = Quarantine()
    entries = q.list_entries()
    if not entries:
        console.print("[dim]Quarantine is empty.[/]")
        return
    table = Table(title="Quarantined files")
    # The ID is what the user types back: never truncate it.
    table.add_column("ID", style="bold", no_wrap=True, min_width=16)
    table.add_column("Verdict")
    table.add_column("When", no_wrap=True)
    table.add_column("Original path", overflow="fold")
    table.add_column("Status")
    table.add_column("Last re-scan")
    for e in entries:
        status_txt = "[yellow]restored[/]" if e.restored else "[red]isolated[/]"
        tags = [t for t, on in (("encrypted", e.encrypted), ("imported", e.imported)) if on]
        if tags:
            status_txt += f" [dim]({', '.join(tags)})[/]"
        rescan = "-"
        if isinstance(e.last_rescan, dict):
            rescan = (f"{'still flagged' if e.last_rescan.get('threat') else 'no longer flagged'} "
                      f"({str(e.last_rescan.get('when', ''))[:10]})")
        table.add_row(_esc(e.id), _esc(e.verdict), _esc(e.quarantined_at.split("T")[0]),
                      _esc(e.original_path), status_txt, _esc(rescan))
    console.print(table)


@quarantine_app.command("restore")
def quarantine_restore(
    entry_id: str = typer.Argument(..., help="Quarantine entry ID (from 'quarantine list')."),
    dest: str | None = typer.Option(None, "--to", help="Restore to this path instead of the original."),
    rescan: bool = typer.Option(False, "--rescan", help="Re-scan with current rules first; ask before restoring if it is still flagged."),
    yes: bool = typer.Option(False, "--yes", "-y", help="With --rescan: restore even if still flagged, without asking."),
):
    """Restore a quarantined file (optionally re-scanning it first)."""
    q = Quarantine()
    try:
        if rescan:
            result = q.rescan(entry_id)
            _print_rescan(entry_id, result)
            if result.is_threat and not yes:
                if not typer.confirm("It is STILL detected as a threat. Restore it anyway?", default=False):
                    console.print("[dim]Left in quarantine.[/]")
                    raise typer.Exit(1)
            elif result.errored and not result.is_threat and not yes:
                if not typer.confirm("An engine could not finish re-scanning it. Restore anyway?", default=False):
                    console.print("[dim]Left in quarantine.[/]")
                    raise typer.Exit(1)
        out = q.restore(entry_id, Path(dest) if dest else None)
    except QuarantineError as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Restored[/] to {_esc(out)}")


def _print_rescan(entry_id: str, result: FileResult) -> None:
    if result.is_threat:
        console.print(f"[red]{_esc(entry_id)}: still detected[/] ({result.verdict.label})")
    elif result.errored:
        console.print(f"[yellow]{_esc(entry_id)}: re-scan incomplete[/] (an engine could not finish)")
    else:
        console.print(f"[green]{_esc(entry_id)}: no longer detected[/] by the current rules")
    for f in result.findings:
        if f.severity >= Severity.LOW:
            console.print(f"    [{_style(f.severity)}]-[/] ({_esc(f.engine)}) [bold]{_esc(f.name)}[/]: "
                          f"{_esc(f.description)}")


@quarantine_app.command("rescan")
def quarantine_rescan(
    entry_id: str | None = typer.Argument(None, help="Quarantine entry ID (omit with --all)."),
    all_items: bool = typer.Option(False, "--all", help="Re-scan every item still in quarantine."),
):
    """Re-check quarantined items against the current rules (they stay isolated).

    Exit code 1 if anything is still detected, 2 if an item could not be re-scanned.
    """
    q = Quarantine()
    if all_items:
        ids = [e.id for e in q.list_entries() if not e.restored]
    elif entry_id:
        ids = [entry_id]
    else:
        console.print("[red]Give an entry ID, or --all.[/]")
        raise typer.Exit(2)
    if not ids:
        console.print("[dim]Nothing in quarantine to re-scan.[/]")
        return
    from .scanner import Scanner
    scanner = Scanner()
    still, failed = 0, 0
    for i in ids:
        try:
            result = q.rescan(i, scanner)
        except QuarantineError as exc:
            failed += 1
            console.print(f"[red]{_esc(i)}: {_esc(exc)}[/]")
            continue
        still += int(result.is_threat)
        failed += int(result.errored and not result.is_threat)
        _print_rescan(i, result)
    raise typer.Exit(2 if failed else (1 if still else 0))


@quarantine_app.command("purge")
def quarantine_purge(
    older_than: str | None = typer.Option(None, "--older-than", help="Only items quarantined longer ago than this (e.g. 30d, 12h, 2w)."),
    expired: bool = typer.Option(False, "--expired", help="Use the 'quarantine_retention_days' setting as the age."),
    restored: bool = typer.Option(False, "--restored", help="Only items that were already restored."),
    all_items: bool = typer.Option(False, "--all", help="Every quarantined item."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be deleted; delete nothing."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
):
    """Permanently delete quarantined items by age or state (cannot be undone)."""
    from .quarantine import parse_age
    cfg = Config.load()
    days: float | None = None
    try:
        if older_than:
            days = parse_age(older_than)
    except ValueError as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(2)
    if expired:
        if cfg.quarantine_retention_days <= 0:
            console.print("[red]No retention period is set.[/] Set one with: "
                          "warden config set quarantine_retention_days 30")
            raise typer.Exit(2)
        days = float(cfg.quarantine_retention_days) if days is None else min(days, cfg.quarantine_retention_days)
    if days is None and not restored and not all_items:
        console.print("[red]Choose what to purge:[/] --older-than, --expired, --restored or --all.")
        raise typer.Exit(2)

    q = Quarantine(cfg)
    selected = q.purge(older_than_days=days, restored_only=restored, everything=all_items, dry_run=True)
    if not selected:
        console.print("[dim]Nothing matches; nothing deleted.[/]")
        return
    for e in selected:
        console.print(f"  {_esc(e.id)}  {_esc(e.quarantined_at[:10])}  {_esc(e.original_path)}")
    if dry_run:
        console.print(f"[dim]{len(selected)} item(s) would be permanently deleted (dry run).[/]")
        return
    if not yes and not typer.confirm(
            f"Permanently delete these {len(selected)} quarantined item(s)? This cannot be undone.",
            default=False):
        console.print("[dim]Cancelled.[/]")
        return
    deleted = q.purge(older_than_days=days, restored_only=restored, everything=all_items)
    console.print(f"[green]Deleted[/] {len(deleted)} quarantined item(s).")


def _bundle_password(flag: bool) -> str | None:
    """Passwords are prompted for (hidden) or read from WARDEN_BUNDLE_PASSWORD -
    never taken from the command line, where they would land in shell history."""
    import os
    if not flag:
        return None
    return os.environ.get("WARDEN_BUNDLE_PASSWORD") or typer.prompt("Bundle password", hide_input=True)


@quarantine_app.command("export")
def quarantine_export(
    entry_id: str = typer.Argument(..., help="Quarantine entry ID."),
    out: str = typer.Argument(..., help="Bundle file to write (e.g. sample.wq)."),
    password: bool = typer.Option(False, "--password", "-p", help="Encrypt the bundle with a password (prompted)."),
):
    """Export a quarantined item as a portable bundle (the payload stays neutralized)."""
    try:
        path = Quarantine().export(entry_id, Path(out), password=_bundle_password(password))
    except QuarantineError as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Exported[/] {_esc(entry_id)} to {_esc(path)}"
                  + (" [dim](password-protected)[/]" if password else ""))
    console.print("[yellow]This bundle contains a file Warden flagged.[/] Share it only with "
                  "someone who expects it.")


@quarantine_app.command("import")
def quarantine_import(
    bundle: str = typer.Argument(..., help="Bundle file created by 'warden quarantine export'."),
    password: bool = typer.Option(False, "--password", "-p", help="The bundle is password-protected (prompted)."),
):
    """Add an exported bundle to this computer's quarantine."""
    try:
        entry = Quarantine().import_bundle(Path(bundle), password=_bundle_password(password))
    except QuarantineError as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Imported[/] as {entry.id} ({_esc(entry.verdict)}, {entry.size:,} bytes).")
    console.print(f"[dim]Re-check it with: warden quarantine rescan {entry.id}[/]")


@quarantine_app.command("delete")
def quarantine_delete(
    entry_id: str = typer.Argument(..., help="Quarantine entry ID to permanently delete."),
):
    """Permanently delete a quarantined file (cannot be undone)."""
    if not typer.confirm(f"Permanently delete quarantined item {entry_id}? This cannot be undone.", default=False):
        console.print("[dim]Cancelled.[/]")
        return
    q = Quarantine()
    try:
        q.delete(entry_id)
    except QuarantineError as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Deleted[/] {_esc(entry_id)}")


@app.command()
def inspect(
    path: str = typer.Argument(..., help="File to describe."),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
):
    """Describe a file: hashes, executable format, code signature, archive contents.

    Read-only and offline. Shows what Warden can see about a file without
    deciding whether it is malicious (use `warden scan` for a verdict).
    """
    from . import binfmt
    from .archive import ArchiveLimits, ArchiveStats, archive_kind, iter_members
    from .engines.base import ScanContext
    from .signature import describe, signature_info

    p = Path(path)
    if not p.is_file():
        console.print(f"[red]Not a file:[/] {_esc(p)}")
        raise typer.Exit(2)
    cfg = Config.load()
    size = p.stat().st_size
    ctx = ScanContext(p, size, cfg.max_scan_bytes)
    data = ctx.data()
    if ctx.read_error:
        console.print(f"[red]Could not read file:[/] {_esc(ctx.read_error)}")
        raise typer.Exit(2)
    info: dict = {"path": str(p), "size": size, "sha256": ctx.sha256(), "sha1": ctx.sha1()}
    binary = binfmt.binary_info(data, size)
    if binary:
        info["binary"] = binary
        if binary.get("format") in ("pe", "macho"):
            info["signature"] = signature_info(p)
    kind = archive_kind(data)
    if kind:
        stats = ArchiveStats()
        members = [(n, len(b)) for n, b in iter_members(data, p.name, ArchiveLimits(), stats)]
        info["archive"] = {
            "kind": kind, "members": [{"name": n, "size": sz} for n, sz in members[:200]],
            "member_count": len(members), "skipped": stats.members_skipped,
            "encrypted": stats.encrypted, "notes": stats.reasons,
        }
    if json_out:
        typer.echo(_json.dumps(info, indent=2))
        return

    table = Table.grid(padding=(0, 2))
    table.add_column(no_wrap=True)
    table.add_column(overflow="fold")
    table.add_row("Path:", _esc(p))
    table.add_row("Size:", f"{size:,} bytes")
    table.add_row("SHA-256:", info["sha256"] or "-")
    table.add_row("SHA-1:", info["sha1"] or "-")
    if binary:
        table.add_row("Format:", _esc(f"{str(binary.get('format')).upper()} "
                                      f"{binary.get('arch', '?')} {binary.get('type', '')}"))
        if binary.get("interpreter"):
            table.add_row("Interpreter:", _esc(binary["interpreter"]))
        names = [s["name"] if isinstance(s, dict) else s
                 for s in (binary.get("sections") or binary.get("segments") or [])]
        if names:
            table.add_row("Sections:", _esc(", ".join(names[:16])))
        if binary.get("imphash"):
            table.add_row("Import hash:", _esc(binary["imphash"]))
        notes = [o.get("id", "?") for o in binary.get("observations", [])]
        if notes:
            table.add_row("Observations:", _esc(", ".join(notes)))
        if "signature" in info:
            table.add_row("Signature:", _esc(describe(info["signature"])))
        elif binary.get("format") == "elf":
            table.add_row("Signature:", "n/a (no platform signing scheme for ELF)")
    else:
        table.add_row("Format:", "not a PE / ELF / Mach-O executable")
    if kind:
        arc = info["archive"]
        table.add_row("Archive:", f"{kind}, {arc['member_count']} member(s)"
                      + (f", {arc['encrypted']} encrypted" if arc["encrypted"] else "")
                      + (f", {arc['skipped']} not readable" if arc["skipped"] else ""))
        for m in arc["members"][:15]:
            table.add_row("", _esc(f"{m['name'][:80]}  ({m['size']:,} bytes)"))
        if arc["member_count"] > 15:
            table.add_row("", f"[dim]…and {arc['member_count'] - 15} more[/]")
    console.print(Panel(table, title="File details", border_style="blue"))


@app.command()
def lookup(
    target: str = typer.Argument(..., help="A file path, or a SHA-256 / SHA-1 hash."),
):
    """Check a file or hash against online reputation (Team Cymru / VirusTotal)."""
    from .engines.base import ScanContext
    from .reputation import OnlineReputation

    cfg = Config.load()
    if net.is_offline(cfg):
        console.print("[red]Offline mode is on:[/] 'lookup' needs the network. "
                      "Drop --offline / WARDEN_OFFLINE / the 'offline' setting to use it.")
        raise typer.Exit(2)
    cfg.online_hash_lookup = True
    rep = OnlineReputation(cfg, max_lookups=1)
    if not rep.available:
        console.print("[red]Online lookup unavailable[/] (httpx not installed).")
        raise typer.Exit(1)

    sha256 = sha1 = None
    p = Path(target)
    if p.is_file():
        ctx = ScanContext(p, p.stat().st_size, cfg.max_scan_bytes)
        sha256, sha1 = ctx.sha256(), ctx.sha1()
    else:
        h = target.strip().lower()
        if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
            sha256 = h
        elif len(h) == 40 and all(c in "0123456789abcdef" for c in h):
            sha1 = h
        else:
            console.print("[red]Not a file or a valid SHA-256/SHA-1 hash.[/]")
            raise typer.Exit(2)

    if rep.provider == "cymru" and not sha1:
        console.print("[yellow]The keyless Team Cymru provider needs a SHA-1 or a file.[/] "
                      "Pass a file, a SHA-1 hash, or set a VirusTotal key for SHA-256 lookups.")
        raise typer.Exit(2)

    console.print(f"[dim]Provider: {rep.status}[/]")
    with console.status("Querying online reputation…"):
        result = rep.check(sha256, sha1)
    audit.record("network.lookup", cfg, provider=rep.provider, sha256=sha256, sha1=sha1,
                 answered=result is not None)

    if result is None:
        console.print("[yellow]No answer[/] (network issue or rate limited). Try again.")
        raise typer.Exit(1)
    if not result.known:
        console.print(Panel.fit(
            f"[green]Not found[/] in {result.source}.\n"
            f"[dim]Unknown to this source — not proof it's clean.[/]",
            border_style="green", title="Reputation"))
        raise typer.Exit(0)
    if result.malicious:
        console.print(Panel.fit(
            f"[bold white on red] KNOWN MALWARE [/]\n{result.detections}",
            border_style="red", title="Reputation"))
        raise typer.Exit(1)
    console.print(Panel.fit(
        f"[green]Known and not flagged as malicious[/]\n{result.detections}",
        border_style="green", title="Reputation"))


@app.command()
def gui(
    port: int = typer.Option(8787, "--port", help="Port to serve on (localhost only)."),
    no_open: bool = typer.Option(False, "--no-open", help="Don't auto-open a browser."),
):
    """Launch the local web dashboard (scan, sweep, history, quarantine)."""
    from .gui import serve
    try:
        serve(port=port, open_browser=not no_open)
    except OSError as exc:
        console.print(f"[red]Could not start dashboard on port {port}:[/] {exc}")
        raise typer.Exit(1)


@app.command("update-rules")
def update_rules():
    """Explain how to add YARA rules and hash feeds."""
    cfg = Config.load()
    cfg.ensure_dirs()
    console.print(Panel.fit(
        f"Drop detection content into your user rules dir:\n\n"
        f"  [cyan]{cfg.rules_user_dir}[/]\n\n"
        f"  * [bold].yar / .yara[/] files       -> extra YARA rules\n"
        f"  * [bold]malware_hashes.txt[/]       -> one SHA-256 per line ('hash  label')\n\n"
        f"Community sources:\n"
        f"  * YARA rules:  github.com/Yara-Rules/rules , github.com/Neo23x0/signature-base\n"
        f"  * Hash feeds:  bazaar.abuse.ch (MalwareBazaar) export\n\n"
        f"Signed, versioned rule packs (with rollback): [bold]warden rules --help[/]\n\n"
        f"For millions of ClamAV signatures, install ClamAV and run [bold]freshclam[/].",
        title="Adding rules & signatures",
        border_style="blue",
    ))


# -- rule packs ----------------------------------------------------------
def _rules_fail(exc: Exception) -> None:
    console.print(f"[red]{_esc(exc)}[/]")
    raise typer.Exit(2)


@rules_app.command("list")
def rules_list():
    """Show installed rule packs (active and rollback versions)."""
    from .rulepacks import RulePackManager
    packs = RulePackManager().packs()
    if not packs:
        console.print("[dim]No rule packs installed. Bundled rules and your own files in the "
                      "user rules folder are always used.[/]")
        return
    table = Table(title="Rule packs")
    table.add_column("Name", style="bold")
    table.add_column("Version", justify="right")
    table.add_column("State")
    table.add_column("Signed by")
    table.add_column("Files", justify="right")
    table.add_column("Installed")
    for p in packs:
        signer = f"{p.signer or 'key'} ({p.key_id})" if p.key_id else "[yellow]unsigned[/]"
        table.add_row(_esc(p.name), str(p.version),
                      "[green]active[/]" if p.active else "[dim]kept for rollback[/]",
                      signer if not p.key_id else _esc(signer), str(p.files),
                      _esc(p.installed_at.split("T")[0]))
    console.print(table)


def _read_pack_source(source: str, sig: str | None) -> tuple[bytes, bytes | None]:
    """Load a pack (and its .sig) from a file path or an https:// URL."""
    from .rulepacks import MAX_PACK_BYTES
    if source.lower().startswith(("http://", "https://")):
        pack = net.download(source, max_bytes=MAX_PACK_BYTES, config=Config.load())
        sig_bytes: bytes | None = None
        try:
            sig_bytes = (Path(sig).read_bytes() if sig
                         else net.download(source + ".sig", max_bytes=64 * 1024, config=Config.load()))
        except net.NetworkError:
            sig_bytes = None
        return pack, sig_bytes
    path = Path(source)
    if not path.is_file():
        raise FileNotFoundError(f"no such pack file: {source}")
    sig_path = Path(sig) if sig else Path(str(path) + ".sig")
    return path.read_bytes(), (sig_path.read_bytes() if sig_path.is_file() else None)


@rules_app.command("install")
def rules_install(
    source: str = typer.Argument(..., help="Pack file (.wrp) or an https:// URL."),
    sig: str | None = typer.Option(None, "--sig", help="Signature file (default: <pack>.sig)."),
    allow_unsigned: bool = typer.Option(False, "--allow-unsigned", help="Install a pack with no signature."),
    allow_downgrade: bool = typer.Option(False, "--allow-downgrade", help="Allow a version older than the active one."),
):
    """Verify and install a rule pack; the previous version is kept for rollback."""
    from .rulepacks import RulePackError, RulePackManager
    try:
        pack, sig_bytes = _read_pack_source(source, sig)
        info = RulePackManager().install(pack, sig_bytes, allow_unsigned=allow_unsigned,
                                         allow_downgrade=allow_downgrade)
    except (RulePackError, net.OfflineError, net.NetworkError, OSError) as exc:
        _rules_fail(exc)
        return
    signed = f"signed by {info.signer or 'key'} ({info.key_id})" if info.key_id else "UNSIGNED"
    console.print(f"[green]Installed[/] {_esc(info.name)} v{info.version} "
                  f"({info.files} file(s), {_esc(signed)}).")
    console.print(f"[dim]Roll back with: warden rules rollback {_esc(info.name)}[/]")


@rules_app.command("verify")
def rules_verify(
    pack: str = typer.Argument(..., help="Pack file (.wrp) to check."),
    sig: str | None = typer.Option(None, "--sig", help="Signature file (default: <pack>.sig)."),
):
    """Check a pack's signature and contents without installing it."""
    from .rulepacks import RulePackError, RulePackManager, read_pack
    try:
        data, sig_bytes = _read_pack_source(pack, sig)
        manifest, files = read_pack(data)
        if sig_bytes is None:
            console.print(f"[yellow]Structure OK, but NOT signed:[/] {_esc(manifest['name'])} "
                          f"v{manifest['version']} ({len(files)} file(s)).")
            raise typer.Exit(1)
        key = RulePackManager().verify(data, sig_bytes)
    except (RulePackError, net.OfflineError, net.NetworkError, OSError) as exc:
        _rules_fail(exc)
        return
    console.print(f"[green]Valid.[/] {_esc(manifest['name'])} v{manifest['version']}, "
                  f"{len(files)} file(s), signed by {_esc(key['name'] or 'key')} ({key['key_id']}).")


@rules_app.command("rollback")
def rules_rollback(name: str = typer.Argument(..., help="Pack name.")):
    """Switch a pack back to its previously active version."""
    from .rulepacks import RulePackError, RulePackManager
    try:
        info = RulePackManager().rollback(name)
    except RulePackError as exc:
        _rules_fail(exc)
        return
    console.print(f"[green]Rolled back[/] {_esc(info.name)} to v{info.version}.")


@rules_app.command("remove")
def rules_remove(name: str = typer.Argument(..., help="Pack name.")):
    """Uninstall a rule pack (all versions)."""
    from .rulepacks import RulePackError, RulePackManager
    try:
        RulePackManager().remove(name)
    except RulePackError as exc:
        _rules_fail(exc)
        return
    console.print(f"[green]Removed[/] rule pack {_esc(name)}.")


@rules_app.command("trust")
def rules_trust(
    public_key: str = typer.Argument(..., help="Public key file (.pub), or the base64 key itself."),
    name: str = typer.Option("", "--name", help="A label for whose key this is."),
):
    """Trust a signing key: packs signed with it can be installed."""
    from .rulepacks import RulePackError, RulePackManager
    p = Path(public_key)
    try:
        text = p.read_text(encoding="utf-8") if p.is_file() else public_key
        kid = RulePackManager().trust(text, name)
    except (RulePackError, OSError) as exc:
        _rules_fail(exc)
        return
    console.print(f"[green]Trusted[/] signing key {kid}" + (f" ({_esc(name)})" if name else "") + ".")


@rules_app.command("untrust")
def rules_untrust(key_id: str = typer.Argument(..., help="Key id (from 'warden rules keys').")):
    """Stop trusting a signing key."""
    from .rulepacks import RulePackError, RulePackManager
    try:
        RulePackManager().untrust(key_id)
    except RulePackError as exc:
        _rules_fail(exc)
        return
    console.print(f"[green]Removed[/] key {_esc(key_id)} from the trust store.")


@rules_app.command("keys")
def rules_keys():
    """List trusted signing keys."""
    from .rulepacks import RulePackManager
    keys = RulePackManager().trusted_keys()
    if not keys:
        console.print("[dim]No trusted signing keys. Add one with 'warden rules trust <key.pub>'.[/]")
        return
    table = Table(title="Trusted rule-pack signing keys")
    table.add_column("Key id", style="bold")
    table.add_column("Name")
    table.add_column("Added")
    for k in keys:
        table.add_row(k["key_id"], _esc(k["name"] or "-"), _esc(k["added"].split("T")[0]))
    console.print(table)


@rules_app.command("keygen")
def rules_keygen(
    name: str = typer.Argument(..., help="Base name for the key files."),
    out: str = typer.Option(".", "--out", help="Folder to write <name>.key and <name>.pub into."),
):
    """Create a signing key pair for publishing your own rule packs."""
    import base64

    from .rulepacks import RulePackError, generate_keypair, key_id
    from .storage import atomic_write_text
    out_dir = Path(out)
    key_path, pub_path = out_dir / f"{name}.key", out_dir / f"{name}.pub"
    if key_path.exists() or pub_path.exists():
        console.print(f"[red]Refusing to overwrite[/] {_esc(key_path)} / {_esc(pub_path)}")
        raise typer.Exit(2)
    try:
        priv, pub = generate_keypair()
        atomic_write_text(key_path, base64.b64encode(priv).decode("ascii") + "\n", mode=0o600)
        atomic_write_text(pub_path, base64.b64encode(pub).decode("ascii") + "\n")
    except (RulePackError, OSError) as exc:
        _rules_fail(exc)
        return
    console.print(f"[green]Created[/] key {key_id(pub)}")
    console.print(f"  private: {_esc(key_path)}  [yellow](keep secret - anyone with it can sign packs)[/]")
    console.print(f"  public:  {_esc(pub_path)}  [dim](share; users run: warden rules trust {_esc(pub_path.name)})[/]")


@rules_app.command("build")
def rules_build(
    folder: str = typer.Argument(..., help="Folder of .yar/.yara rules and/or malware_hashes.txt."),
    name: str = typer.Option(..., "--name", help="Pack name (a-z, 0-9, '-', '_')."),
    version: int = typer.Option(..., "--version", help="Pack version (a positive integer; must increase)."),
    description: str = typer.Option("", "--description", help="Short description."),
    key: str | None = typer.Option(None, "--key", help="Private key file to sign the pack with."),
    out: str | None = typer.Option(None, "--out", help="Output file (default: <name>-<version>.wrp)."),
):
    """Build (and optionally sign) a rule pack from a folder of rules."""
    from .rulepacks import RulePackError, _compile_check, _decode_key, build_pack, read_pack, sign_pack
    from .storage import atomic_write_bytes
    try:
        pack = build_pack(Path(folder), name, version, description)
        _manifest, files = read_pack(pack)
        _compile_check(files)
        out_path = Path(out or f"{name}-{version}.wrp")
        atomic_write_bytes(out_path, pack)
        console.print(f"[green]Built[/] {_esc(out_path)} ({len(files)} file(s)).")
        if key:
            sig_doc = sign_pack(pack, _decode_key(Path(key).read_text(encoding="utf-8"), "private key"))
            atomic_write_bytes(Path(str(out_path) + ".sig"), sig_doc)
            console.print(f"[green]Signed[/] {_esc(str(out_path) + '.sig')}")
        else:
            console.print("[yellow]Not signed.[/] Sign it with: warden rules sign "
                          f"{_esc(out_path)} --key <name>.key")
    except (RulePackError, OSError) as exc:
        _rules_fail(exc)


@rules_app.command("sign")
def rules_sign(
    pack: str = typer.Argument(..., help="Pack file to sign."),
    key: str = typer.Option(..., "--key", help="Private key file (from 'warden rules keygen')."),
):
    """Write a detached signature (<pack>.sig) for a rule pack."""
    from .rulepacks import RulePackError, _decode_key, read_pack, sign_pack
    from .storage import atomic_write_bytes
    try:
        data = Path(pack).read_bytes()
        read_pack(data)     # never sign something that isn't a well-formed pack
        sig_doc = sign_pack(data, _decode_key(Path(key).read_text(encoding="utf-8"), "private key"))
        atomic_write_bytes(Path(pack + ".sig"), sig_doc)
    except (RulePackError, OSError) as exc:
        _rules_fail(exc)
        return
    console.print(f"[green]Signed[/] {_esc(pack + '.sig')}")


# -- history subcommands -------------------------------------------------
@history_app.command("list")
def history_list(
    limit: int = typer.Option(20, "--limit", "-n", help="Max entries to show."),
):
    """List past scan/sweep reports."""
    entries = History().list(limit=limit)
    if not entries:
        console.print("[dim]No history yet. Run a scan/sweep with --save.[/]")
        return
    table = Table(title="Scan history")
    table.add_column("ID", style="bold", no_wrap=True, min_width=27)
    table.add_column("Kind")
    table.add_column("When (UTC)")
    table.add_column("Files", justify="right")
    table.add_column("Threats", justify="right")
    table.add_column("Target")
    for e in entries:
        threat_cell = f"[red]{e.threats}[/]" if e.threats else "0"
        table.add_row(_esc(e.id), _esc(e.kind), _esc(e.when.replace("T", " ")[:19]),
                      str(e.files_scanned), threat_cell, _esc(e.root))
    console.print(table)


@history_app.command("show")
def history_show(entry_id: str = typer.Argument(..., help="History ID (or prefix).")):
    """Show the threats from a saved report."""
    data = History().load(entry_id)
    if data is None:
        console.print(f"[red]No history entry matching[/] {entry_id}")
        raise typer.Exit(2)
    console.print(f"[bold]{_esc(data.get('id'))}[/]  kind={_esc(data.get('kind'))}  target={_esc(data.get('root'))}")
    console.print(f"files scanned: {data.get('files_scanned')}  threats: {data.get('threats')}  "
                  f"duration: {data.get('duration_seconds')}s")
    threats = [r for r in data.get("results", []) if r.get("verdict", 0) >= int(Severity.MEDIUM)]
    if not threats:
        console.print("[green]No threats in this report.[/]")
        return
    for r in threats:
        sev = Severity(r["verdict"])
        console.print(f"\n[{_style(sev)}] {sev.label}[/] {_esc(r['path'])}")
        for f in r.get("findings", []):
            fsev = Severity(f["severity"])
            console.print(f"    [{_style(fsev)}]-[/] ({_esc(f['engine'])}) [bold]{_esc(f['name'])}[/]: {_esc(f['description'])}")


@history_app.command("prune")
def history_prune(
    keep: int | None = typer.Option(None, "--keep", help="Keep only the most recent N reports (default 50)."),
    older_than: str | None = typer.Option(None, "--older-than", help="Delete reports older than this (e.g. 90d, 12w)."),
):
    """Delete old history: keep the most recent N, or drop everything older than an age.

    To do this automatically, set a retention period:
    warden config set history_retention_days 90
    """
    from .quarantine import parse_age
    history = History()
    if older_than is not None:
        try:
            days = parse_age(older_than)
        except ValueError as exc:
            console.print(f"[red]{_esc(exc)}[/]")
            raise typer.Exit(2)
        removed = history.expire(days)
        console.print(f"[green]Pruned {removed} report(s)[/] older than {_esc(older_than)}.")
        if keep is None:
            return
    keep = 50 if keep is None else keep
    removed = history.prune(keep=keep)
    console.print(f"[green]Pruned {removed} old report(s).[/] Kept {keep}.")


# -- schedule subcommands ------------------------------------------------
@schedule_app.command("add")
def schedule_add(
    name: str = typer.Argument(..., help="Unique name for this schedule."),
    kind: str = typer.Option("sweep", "--kind", help="'sweep' or 'scan'."),
    target: str = typer.Option("", "--target", help="Path to scan (required for --kind scan)."),
    frequency: str = typer.Option("daily", "--frequency", "-f", help="hourly | daily | weekly."),
    at: str = typer.Option("03:00", "--at", help="Time of day HH:MM (24h); ignored for hourly."),
    quick: bool = typer.Option(False, "--quick", help="Use quick mode (sweep only)."),
    min_severity: str = typer.Option("low", "--min-severity", help="Report threshold."),
):
    """Register a recurring scan with the OS scheduler (writes results to history)."""
    spec = ScheduleSpec(
        name=name, kind=kind, target=target, frequency=frequency,
        time=at, quick=quick, min_severity=min_severity,
    )
    try:
        detail = Scheduler().add(spec)
    except SchedulerError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Scheduled '{name}'[/] ({kind}, {frequency} at {at}).")
    console.print(f"[dim]{detail}[/]")
    console.print(f"[dim]Runs: {' '.join(spec.command_args())}[/]")


@schedule_app.command("list")
def schedule_list():
    """List Warden's scheduled scans."""
    specs = Scheduler().list()
    if not specs:
        console.print("[dim]No schedules. Add one with 'warden schedule add'.[/]")
        return
    table = Table(title="Warden schedules")
    table.add_column("Name", style="bold")
    table.add_column("Kind")
    table.add_column("Frequency")
    table.add_column("At")
    table.add_column("Target")
    for s in specs:
        table.add_row(_esc(s.name), _esc(s.kind), _esc(s.frequency),
                      _esc(s.time) if s.frequency != "hourly" else "-", _esc(s.target or "-"))
    console.print(table)


@schedule_app.command("doctor")
def schedule_doctor(
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
):
    """Check that scheduled scans will really run (and whether they have been).

    Compares Warden's registry with the OS scheduler: missing or disabled
    tasks, a task pointing at a Warden that has moved, a target folder that no
    longer exists, a stopped cron daemon, failed last runs and orphaned tasks.
    Exit code 1 if any problem is found.
    """
    diagnoses, general = Scheduler().diagnose()
    problems = bool(general) or any(not d.ok for d in diagnoses)
    if json_out:
        typer.echo(_json.dumps({"schedules": [d.to_dict() for d in diagnoses],
                                "general": general, "ok": not problems}, indent=2))
        raise typer.Exit(1 if problems else 0)

    if not diagnoses and not general:
        console.print("[dim]No schedules to check. Add one with 'warden schedule add'.[/]")
        return
    table = Table(title="Schedule health")
    table.add_column("Name", style="bold")
    table.add_column("Health")
    table.add_column("State")
    table.add_column("Last result / run")
    table.add_column("Next run")
    for d in diagnoses:
        health = "[green]OK[/]" if d.ok else f"[red]{len(d.problems)} problem(s)[/]"
        last = d.info.get("last_result") or d.info.get("last_recorded_run") or "-"
        table.add_row(_esc(d.name), health, _esc(d.info.get("state") or "-"),
                      _esc(str(last)[:60]), _esc(d.info.get("next_run") or "-"))
    if diagnoses:
        console.print(table)
    for d in diagnoses:
        for p in d.problems:
            console.print(f"[red]x {_esc(d.name)}:[/] {_esc(p)}")
        for n in d.notes:
            console.print(f"[yellow]! {_esc(d.name)}:[/] {_esc(n)}")
    for g in general:
        console.print(f"[red]x[/] {_esc(g)}")
    if not problems:
        console.print("[green]All scheduled scans look healthy.[/]")
    raise typer.Exit(1 if problems else 0)


@schedule_app.command("test")
def schedule_test(
    name: str = typer.Argument(..., help="Schedule to run once, now."),
    timeout: float = typer.Option(0, "--timeout", min=0, help="Give up after this many seconds (0 = wait)."),
    via_scheduler: bool = typer.Option(False, "--via-scheduler", help="Windows: start the real task through Task Scheduler."),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
):
    """Run a scheduled scan once, right now, the way the OS scheduler would.

    Uses the exact registered command in a stripped-down environment (like
    cron's), then confirms a report reached history. Exit code 0 if it ran and
    saved a report (even if it found threats), 1 if it could not run properly.
    """
    try:
        with console.status(f"Running schedule '{_esc(name)}' now…"):
            res = Scheduler().test_run(name, timeout=timeout or None, via_scheduler=via_scheduler)
    except SchedulerError as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(1)
    audit.record("schedule.test", None, name=res["name"], exit_code=res["exit_code"],
                 ok=res["ok"], history_saved=res["history_saved"])
    if json_out:
        typer.echo(_json.dumps(res, indent=2))
        raise typer.Exit(0 if res["ok"] else 1)
    console.print(f"[dim]Ran:[/] {_esc(' '.join(res['command']))}")
    style = "red" if res["failed_to_run"] else ("yellow" if res["exit_code"] else "green")
    console.print(f"[{style}]Result:[/] {_esc(res['result'])} "
                  f"[dim](exit code {res['exit_code']}, {res['duration_seconds']}s)[/]")
    if res["history_saved"]:
        console.print(f"[green]A report was saved to history[/] ({_esc(', '.join(res['history_ids']))}).")
    else:
        console.print("[red]No report reached history[/] - a scheduled run would leave no record.")
    if not res["ok"] and res["output_tail"]:
        console.print("[dim]Last output:[/]")
        for line in res["output_tail"]:
            console.print(f"  {_esc(line)}")
    raise typer.Exit(0 if res["ok"] else 1)


@schedule_app.command("remove")
def schedule_remove(name: str = typer.Argument(..., help="Schedule name to remove.")):
    """Remove a scheduled scan."""
    try:
        Scheduler().remove(name)
    except SchedulerError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Removed schedule[/] {name}")


# -- config subcommands --------------------------------------------------
# name -> (type, help)
_CONFIG_FIELDS = {
    "online_hash_lookup": (bool, "Enable online hash reputation by default."),
    "offline": (bool, "Hard switch: never use the network (overrides online lookups)."),
    "use_clamav": (bool, "Use ClamAV if its binaries are on PATH."),
    "follow_symlinks": (bool, "Follow symlinks when walking folders."),
    "scan_archives": (bool, "Look inside zip/tar/gzip archives (bounded)."),
    "check_signatures": (bool, "Ask the OS for the publisher signature of flagged executables."),
    "quarantine_encryption": (bool, "Seal newly quarantined files with AES-256-GCM (key in the OS secret store)."),
    "quarantine_retention_days": (int, "Age in days used by 'quarantine purge --expired' (0 = keep until deleted)."),
    "history_retention_days": (int, "Automatically delete saved reports older than this many days (0 = keep)."),
    "audit_log": (bool, "Keep the append-only audit trail of actions (see 'warden audit')."),
    "max_scan_bytes": (int, "Max file size (bytes) for deep content scanning."),
}
# The VirusTotal key is managed separately via `set-vt-key` (OS secret store).
_SECRET_FIELDS: set[str] = set()


def _resolve_vt_key() -> tuple[str, str]:
    """Return (key, source) resolving env -> secret store -> legacy config."""
    import os as _os

    from . import secrets as _secrets
    if _os.environ.get("WARDEN_VT_API_KEY"):
        return _os.environ["WARDEN_VT_API_KEY"], "environment"
    stored = _secrets.load_secret("virustotal_api_key")
    if stored:
        return stored, _secrets.backend_name()
    legacy = getattr(Config.load(), "virustotal_api_key", "")
    if legacy:
        return legacy, "legacy config.json (run set-vt-key to migrate)"
    return "", "not set"


def _parse_bool(value: str) -> bool:
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on", "y"):
        return True
    if v in ("0", "false", "no", "off", "n"):
        return False
    raise ValueError(f"expected true/false, got {value!r}")


def _mask(value: str) -> str:
    if not value:
        return "[dim](not set)[/]"
    return "•" * max(0, len(value) - 4) + value[-4:]


@config_app.command("show")
def config_show():
    """Show current settings."""
    cfg = Config.load()
    table = Table(title="Warden configuration")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    for name in _CONFIG_FIELDS:
        table.add_row(name, str(getattr(cfg, name)))
    vt_key, vt_source = _resolve_vt_key()
    table.add_row("virustotal_api_key", f"{_mask(vt_key)}  [dim]({vt_source})[/]")
    console.print(table)
    console.print(f"[dim]Config file: {cfg.config_path}[/]")


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Setting name."),
    reveal: bool = typer.Option(False, "--reveal", help="Show secret values in full."),
):
    """Print one setting's value."""
    if key not in _CONFIG_FIELDS:
        console.print(f"[red]Unknown setting[/] '{key}'. Options: {', '.join(_CONFIG_FIELDS)}")
        raise typer.Exit(2)
    cfg = Config.load()
    val = getattr(cfg, key)
    if key in _SECRET_FIELDS and not reveal:
        val = _mask(str(val))
    console.print(val)


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Setting name."),
    value: str = typer.Argument(..., help="New value."),
):
    """Set a setting and save it."""
    if key not in _CONFIG_FIELDS:
        console.print(f"[red]Unknown setting[/] '{key}'. Options: {', '.join(_CONFIG_FIELDS)}")
        raise typer.Exit(2)
    typ = _CONFIG_FIELDS[key][0]
    cfg = Config.load()
    try:
        coerced = _parse_bool(value) if typ is bool else typ(value)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]Invalid value for {key}:[/] {exc}")
        raise typer.Exit(2)
    previous = getattr(cfg, key)
    # Record a change that switches the audit trail off while it is still on.
    if key == "audit_log" and previous and not coerced:
        audit.record("config.set", cfg, setting=key, value=False, previous=True)
    setattr(cfg, key, coerced)
    cfg.save()
    saved = getattr(Config.load(), key)     # what actually took effect (values are clamped)
    if key != "audit_log" or saved:
        audit.record("config.set", Config.load(), setting=key, value=saved, previous=previous)
    shown = _mask(str(saved)) if key in _SECRET_FIELDS else str(saved)
    console.print(f"[green]Set[/] {key} = {shown}")
    if saved != coerced:
        console.print(f"[yellow]Note:[/] {coerced!r} is outside the allowed range; using {saved!r}.")


@config_app.command("unset")
def config_unset(key: str = typer.Argument(..., help="Setting name to clear/reset.")):
    """Reset a setting to its default."""
    if key not in _CONFIG_FIELDS:
        console.print(f"[red]Unknown setting[/] '{key}'. Options: {', '.join(_CONFIG_FIELDS)}")
        raise typer.Exit(2)
    default = getattr(Config(), key)
    cfg = Config.load()
    previous = getattr(cfg, key)
    setattr(cfg, key, default)
    cfg.save()
    audit.record("config.set", Config.load(), setting=key, value=default, previous=previous, reset=True)
    console.print(f"[green]Reset[/] {key} to default ({default!r})")


@config_app.command("set-vt-key")
def config_set_vt_key(
    key: str | None = typer.Argument(None, help="VirusTotal API key. Omit to be prompted (hidden)."),
    enable: bool = typer.Option(True, "--enable/--no-enable", help="Also turn on online lookups."),
):
    """Store your VirusTotal API key (prompts hidden if omitted, keeping it out of shell history)."""
    if not key:
        key = typer.prompt("VirusTotal API key", hide_input=True)
    key = key.strip()
    if not key:
        console.print("[yellow]No key entered; nothing changed.[/]")
        raise typer.Exit(1)
    from . import secrets as _secrets
    _secrets.store_secret("virustotal_api_key", key)
    cfg = Config.load()
    # Scrub any legacy plaintext key from config.json and (optionally) enable.
    cfg.virustotal_api_key = ""
    if enable:
        cfg.online_hash_lookup = True
    cfg.save()
    # The key itself is never written to the audit trail - only that it was set.
    audit.record("config.set", cfg, setting="virustotal_api_key", value="(secret stored)",
                 backend=_secrets.backend_name(), online_hash_lookup=cfg.online_hash_lookup)
    console.print(f"[green]Saved VirusTotal key[/] ({_mask(key)}) to the OS secret store "
                  f"([bold]{_secrets.backend_name()}[/]).")
    if enable:
        console.print("[dim]Online reputation is now enabled by default. Disable with:[/] warden config set online_hash_lookup false")


@config_app.command("path")
def config_path():
    """Print the path to the config file."""
    console.print(str(Config.load().config_path))


# -- privacy -------------------------------------------------------------
def _count(path: Path, pattern: str) -> int:
    try:
        return sum(1 for _ in path.glob(pattern))
    except OSError:
        return 0


def _line_count(path: Path) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def privacy_report(cfg: Config) -> dict:
    """Everything Warden stores and every way it can touch the network."""
    from . import secrets as _secrets
    from .reputation import OnlineReputation

    offline = net.is_offline(cfg)
    vt_key, vt_source = _resolve_vt_key()
    cache = cfg.cache_dir / "reputation.json"
    try:
        cached = len(_json.loads(cache.read_text(encoding="utf-8"))) if cache.exists() else 0
    except (OSError, ValueError, TypeError):
        cached = 0
    provider = "none"
    if cfg.online_hash_lookup and not offline:
        provider = OnlineReputation(cfg).provider
    return {
        "telemetry": "none - Warden has no analytics, crash reporting, update checks or accounts",
        "network": {
            "offline_mode": offline,
            "online_hash_lookup_enabled": bool(cfg.online_hash_lookup) and not offline,
            "provider_in_use": provider,
            "what_is_sent": "only a file's SHA-1/SHA-256 hash - never file contents, names or paths",
            "destinations": {
                "cymru": "cloudflare-dns.com (DNS-over-HTTPS query to Team Cymru's hash registry)",
                "virustotal": "www.virustotal.com (only if you stored a VirusTotal API key)",
                "rule packs": "only the URL you pass to 'warden rules install <url>'",
            },
            "when": "only when you pass --online, set online_hash_lookup, run 'warden lookup', "
                    "or install a rule pack from a URL",
        },
        "stored_on_this_computer": {
            "data_dir": str(cfg.data_dir),
            "config": str(cfg.config_path),
            "history_reports": {
                "count": _count(cfg.history_dir, "*.json"), "path": str(cfg.history_dir),
                "contains": "absolute file paths, file hashes, sizes and finding details for "
                            "every scan saved with --save (and every dashboard/scheduled scan)",
            },
            "quarantine_items": {
                "count": _count(cfg.quarantine_dir, "*.qbin") + _count(cfg.quarantine_dir, "*.qenc"),
                "path": str(cfg.quarantine_dir),
                "contains": "neutralized copies of quarantined files plus their original "
                            "absolute paths, hashes and findings",
            },
            "reputation_cache": {
                "count": cached, "path": str(cache),
                "contains": "hashes you looked up online and the answers",
            },
            "audit_log": {
                "enabled": bool(cfg.audit_log),
                "count": _line_count(cfg.data_dir / "audit" / "audit.jsonl"),
                "path": str(cfg.data_dir / "audit" / "audit.jsonl"),
                "contains": "one line per action (scan run, file quarantined/restored/deleted, "
                            "setting changed, rules installed): time, OS user name, host name, "
                            "and the paths involved - never file contents or secrets",
            },
            "retention": {
                "history_retention_days": cfg.history_retention_days,
                "quarantine_retention_days": cfg.quarantine_retention_days,
            },
            "schedules": str(cfg.data_dir / "schedules.json"),
            "virustotal_key": {"stored": bool(vt_key), "where": vt_source,
                               "secret_backend": _secrets.backend_name()},
        },
        "how_to_erase": [
            "warden history prune --keep 0     (delete saved reports)",
            "warden quarantine purge --all     (permanently delete quarantined items)",
            "warden audit prune --older-than 0d  (clear the audit trail; leaves a record that it was cleared)",
            f"delete the folder {cfg.data_dir}  (removes everything Warden stores)",
        ],
    }


@app.command()
def privacy(
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
):
    """Show exactly what Warden stores on this computer and what it sends anywhere.

    Short version: nothing leaves your machine unless you turn on online hash
    lookups, and there is no telemetry of any kind.
    """
    cfg = Config.load()
    rep = privacy_report(cfg)
    if json_out:
        typer.echo(_json.dumps(rep, indent=2))
        return
    n = rep["network"]
    s = rep["stored_on_this_computer"]
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True, style="bold")
    grid.add_column(overflow="fold")
    grid.add_row("Telemetry", "[green]None.[/] No analytics, crash reports, update checks or accounts.")
    if n["offline_mode"]:
        net_line = "[green]Offline mode is ON[/] - Warden cannot use the network at all."
    elif n["online_hash_lookup_enabled"]:
        net_line = (f"[yellow]Online hash lookups are ON[/] (provider: {n['provider_in_use']}). "
                    f"Hashes of scanned executables/documents are sent.")
    else:
        net_line = "[green]Off.[/] With current settings Warden makes no network connections."
    grid.add_row("Network", net_line)
    grid.add_row("If enabled, sends", n["what_is_sent"])
    grid.add_row("...to", "; ".join(f"{k}: {v}" for k, v in n["destinations"].items()))
    grid.add_row("...only when", n["when"])
    grid.add_row("", "")
    grid.add_row("Data folder", _esc(s["data_dir"]))
    h, q, c = s["history_reports"], s["quarantine_items"], s["reputation_cache"]
    grid.add_row("Scan history", f"{h['count']} report(s) - {h['contains']}")
    grid.add_row("Quarantine", f"{q['count']} item(s) - {q['contains']}")
    grid.add_row("Lookup cache", f"{c['count']} entr(ies) - {c['contains']}")
    a = s["audit_log"]
    grid.add_row("Audit trail", (f"{a['count']} entr(ies) - {a['contains']}" if a["enabled"]
                                 else "turned off (audit_log = false)"))
    r = s["retention"]
    grid.add_row("Retention", "history: " + (f"{r['history_retention_days']} days" if r["history_retention_days"] else "kept until you delete it")
                 + "; quarantine: " + (f"{r['quarantine_retention_days']} days (applied by 'quarantine purge --expired')"
                                       if r["quarantine_retention_days"] else "kept until you delete it"))
    k = s["virustotal_key"]
    grid.add_row("VirusTotal key", (f"stored ({_esc(k['where'])})" if k["stored"] else "not set"))
    grid.add_row("", "")
    grid.add_row("To erase", "\n".join(_esc(x) for x in rep["how_to_erase"]))
    console.print(Panel(grid, title="Warden privacy report", border_style="blue"))


# -- audit trail ---------------------------------------------------------
@audit_app.command("show")
def audit_show(
    limit: int = typer.Option(30, "--limit", "-n", min=1, help="How many of the most recent entries to show."),
    event: str | None = typer.Option(None, "--event", help="Only events starting with this (e.g. quarantine, config.set)."),
    since: str | None = typer.Option(None, "--since", help="Only entries newer than this age (e.g. 7d, 12h)."),
    json_out: bool = typer.Option(False, "--json", help="Print the entries as JSON Lines."),
):
    """Show recent audit entries: what Warden did, when, and as which user."""
    from .quarantine import parse_age
    days = None
    if since:
        try:
            days = parse_age(since)
        except ValueError as exc:
            console.print(f"[red]{_esc(exc)}[/]")
            raise typer.Exit(2)
    log = audit.AuditLog()
    entries = log.entries(limit=limit, event=event, since_days=days)
    if json_out:
        for e in entries:
            typer.echo(_json.dumps(e, separators=(",", ":")))
        return
    if not entries:
        console.print("[dim]No audit entries" + ("" if log.enabled else " (the audit log is turned off)") + ".[/]")
        return
    table = Table(title="Audit trail (oldest first)")
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("When (UTC)", no_wrap=True)
    table.add_column("User")
    table.add_column("Event", style="bold")
    table.add_column("Details", overflow="fold")
    for e in entries:
        details: dict = e["details"] if isinstance(e.get("details"), dict) else {}
        actor: dict = e["actor"] if isinstance(e.get("actor"), dict) else {}
        shown = ", ".join(f"{k}={v}" for k, v in details.items() if v not in (None, "", [], False))
        table.add_row(_esc(e.get("seq", "?")), _esc(str(e.get("ts", ""))[:19].replace("T", " ")),
                      _esc(actor.get("user", "?")), _esc(e.get("event", "?")), _esc(shown[:300]))
    console.print(table)


@audit_app.command("verify")
def audit_verify(json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON.")):
    """Check that the audit trail has not been edited (re-walks its hash chain).

    Exit code 0 if the chain is intact, 1 if entries were modified, removed or
    reordered. Record the head hash somewhere else to detect a full rewrite.
    """
    res = audit.AuditLog().verify()
    if json_out:
        typer.echo(_json.dumps(res, indent=2))
        raise typer.Exit(0 if res["ok"] else 1)
    if not res["enabled"]:
        console.print("[yellow]The audit log is turned off[/] (audit_log = false); nothing new is being recorded.")
    if res["ok"]:
        console.print(f"[green]Audit trail intact:[/] {res['entries']} entr(ies)"
                      + (f", {str(res['first'])[:10]} to {str(res['last'])[:10]}" if res["entries"] else "") + ".")
        if res["head_hash"]:
            console.print(f"[dim]Head hash:[/] {res['head_hash']}")
    else:
        console.print(f"[red]Audit trail FAILED verification[/] ({res['entries']} entr(ies) read):")
        for p in res["problems"]:
            console.print(f"  [red]x[/] {_esc(p)}")
    raise typer.Exit(0 if res["ok"] else 1)


@audit_app.command("export")
def audit_export(out: str = typer.Argument(..., help="File to write (JSON Lines).")):
    """Copy the audit trail to a file, e.g. to hand to an auditor or a log collector."""
    try:
        res = audit.AuditLog().export(Path(out))
    except (audit.AuditError, OSError) as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Exported[/] {res['entries']} entr(ies) to {_esc(out)}"
                  + ("" if res["ok"] else " [red](the chain did NOT verify - see 'warden audit verify')[/]"))
    if res["head_hash"]:
        console.print(f"[dim]Head hash:[/] {res['head_hash']}")


@audit_app.command("prune")
def audit_prune(
    older_than: str = typer.Option(..., "--older-than", help="Remove entries older than this (e.g. 365d, 52w)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
):
    """Remove old audit entries. The removal itself is recorded, and the chain stays verifiable."""
    from .quarantine import parse_age
    try:
        days = parse_age(older_than)
    except ValueError as exc:
        console.print(f"[red]{_esc(exc)}[/]")
        raise typer.Exit(2)
    if not yes and not typer.confirm(
            f"Permanently remove audit entries older than {older_than}? This cannot be undone.", default=False):
        console.print("[dim]Cancelled.[/]")
        return
    removed = audit.AuditLog().prune(days)
    console.print(f"[green]Removed[/] {removed} audit entr(ies) older than {_esc(older_than)}.")


# -- licenses ------------------------------------------------------------
@app.command()
def licenses(
    full: bool = typer.Option(False, "--full", help="Print every license text, not just the list."),
):
    """Show the licenses of Warden and the third-party software it includes."""
    from . import notices
    if full:
        typer.echo(notices.notices_text())
        return
    text = notices.notices_text()
    listed = [ln[4:] for ln in text.splitlines() if ln.startswith("  - ")]
    table = Table(title="Warden and bundled third-party software")
    table.add_column("Component", style="bold")
    table.add_column("License")
    for row in listed:
        name, _, lic = row.rpartition("  (")
        table.add_row(_esc(name), _esc(lic.rstrip(")")))
    console.print(table)
    console.print("[dim]Full license texts: warden licenses --full[/]")


# -- posture -------------------------------------------------------------
def posture_report(cfg: Config) -> dict:
    """A point-in-time summary of the settings and state that security reviews
    ask about. Each check is 'ok', 'attention' (a recommendation applies) or
    'info'. Nothing here is sent anywhere."""
    from . import secrets as _secrets
    from .rulepacks import RulePackManager

    checks: list[dict] = []

    def add(cid: str, title: str, status: str, detail: str, advice: str = "") -> None:
        checks.append({"id": cid, "title": title, "status": status, "detail": detail, "advice": advice})

    scanner = Scanner(cfg)
    active, inactive = scanner.active_engines(), scanner.inactive_engines()
    core_ok = "yara" in active and not scanner.engine_warnings
    add("engines", "Detection engines", "ok" if core_ok else "attention",
        f"active: {', '.join(active) or 'none'}; not active: "
        + (", ".join(f"{k} ({v})" for k, v in inactive.items()) or "none")
        + ("; " + "; ".join(scanner.engine_warnings) if scanner.engine_warnings else ""),
        "" if core_ok else "A core engine or rule set failed to load - scans will be reported incomplete.")

    db = scanner.clamav.database_info()
    if not scanner.clamav.available():
        add("signatures", "Signature database (ClamAV)", "info", "ClamAV is not installed (optional)",
            "Install ClamAV and run freshclam for broad signature coverage.")
    else:
        stale = scanner.clamav.freshness_advisory()
        add("signatures", "Signature database (ClamAV)", "attention" if stale else "ok",
            stale or f"version {db.get('version') if db else '?'}, {db.get('age_days') if db else '?'} day(s) old",
            "Run freshclam (ideally on a schedule)." if stale else "")

    packs = [p for p in RulePackManager(cfg).packs() if p.active]
    unsigned = [p.name for p in packs if not p.key_id]
    add("rules", "Rule packs", "attention" if unsigned else "info",
        (f"{len(packs)} active" + (f"; unsigned: {', '.join(unsigned)}" if unsigned else "; all signed")) if packs
        else "none installed (bundled rules and your own rule files are in use)",
        "Prefer packs signed by a key you trust." if unsigned else "")

    diagnoses, general = Scheduler(cfg).diagnose()
    broken = [d.name for d in diagnoses if not d.ok]
    if not diagnoses:
        add("schedule", "Recurring scans", "attention", "no scan is scheduled",
            "Warden only scans when asked. Add one: warden schedule add nightly --kind sweep --frequency daily")
    else:
        add("schedule", "Recurring scans", "attention" if broken or general else "ok",
            f"{len(diagnoses)} scheduled" + (f"; problems with: {', '.join(broken)}" if broken else "")
            + ("; " + "; ".join(general) if general else ""),
            "Run 'warden schedule doctor' for details." if broken or general else "")

    recent = History(cfg).list(limit=1)
    if recent:
        last = recent[0]
        add("last_scan", "Most recent saved scan", "attention" if last.threats else "ok",
            f"{last.kind} of {last.root} at {last.when[:19].replace('T', ' ')} UTC - {last.threats} threat(s)",
            "Review it: warden history show " + last.id if last.threats else "")
    else:
        add("last_scan", "Most recent saved scan", "attention", "no saved scan on record",
            "Run 'warden sweep --save' (dashboard and scheduled scans are saved automatically).")

    q_entries = [e for e in Quarantine(cfg).list_entries() if not e.restored]
    plain = sum(1 for e in q_entries if not e.encrypted)
    add("quarantine", "Quarantine at rest",
        "ok" if cfg.quarantine_encryption and not plain else ("attention" if q_entries or not cfg.quarantine_encryption else "ok"),
        f"{len(q_entries)} item(s) held; encryption " + ("ON (AES-256-GCM)" if cfg.quarantine_encryption else "off (items are only neutralized)")
        + (f"; {plain} item(s) stored without encryption" if plain and cfg.quarantine_encryption else ""),
        "" if cfg.quarantine_encryption and not plain else
        "If quarantined files may hold sensitive data: warden config set quarantine_encryption true")

    offline = net.is_offline(cfg)
    add("network", "Network use", "ok" if offline or not cfg.online_hash_lookup else "info",
        "offline mode - no network access" if offline else
        ("online hash reputation is ON (file hashes are sent to the provider)" if cfg.online_hash_lookup
         else "none (online lookups are off)"),
        "" if offline or not cfg.online_hash_lookup else "Set 'offline true' if hashes must not leave this machine.")

    log = audit.AuditLog(cfg)
    verified = log.verify()
    if not log.enabled:
        add("audit", "Audit trail", "attention", "turned off", "warden config set audit_log true")
    else:
        add("audit", "Audit trail", "ok" if verified["ok"] else "attention",
            f"{verified['entries']} entr(ies), chain " + ("intact" if verified["ok"] else "FAILED verification"),
            "" if verified["ok"] else "Run 'warden audit verify' - the log was modified or damaged.")

    add("retention", "Data retention", "info",
        "history: " + (f"{cfg.history_retention_days} days" if cfg.history_retention_days else "kept indefinitely")
        + "; quarantine: " + (f"{cfg.quarantine_retention_days} days" if cfg.quarantine_retention_days else "kept indefinitely"),
        "" if cfg.history_retention_days else
        "Saved reports list file paths. To limit how long they are kept: warden config set history_retention_days 90")

    if sys.platform == "win32":
        add("data_dir", "Data folder access", "info",
            f"{cfg.data_dir} (protected by your Windows profile's permissions)", "")
    else:
        try:
            mode = cfg.data_dir.stat().st_mode & 0o777
            add("data_dir", "Data folder access", "ok" if mode & 0o077 == 0 else "attention",
                f"{cfg.data_dir} mode {mode:03o}", "" if mode & 0o077 == 0 else f"chmod 700 {cfg.data_dir}")
        except OSError:
            add("data_dir", "Data folder access", "info", f"{cfg.data_dir} does not exist yet", "")

    backend = _secrets.backend_name()
    add("secrets", "Secret storage", "attention" if backend == "owner-only file" else "ok",
        backend, "No OS keychain was found; secrets fall back to an owner-only file." if backend == "owner-only file" else "")

    add("realtime", "Real-time protection", "info",
        "Warden is on-demand only: it does not monitor files as they are opened or run",
        "Keep your operating system's real-time antivirus enabled alongside Warden.")

    return {
        "generated": audit.now_iso(), "warden_version": __version__,
        "host": audit._actor()["host"], "platform": sys.platform,
        "attention": sum(1 for c in checks if c["status"] == "attention"),
        "checks": checks,
    }


@app.command()
def posture(
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON (suitable as audit evidence)."),
    strict: bool = typer.Option(False, "--strict", help="Exit with code 1 if any check needs attention."),
):
    """Summarize this installation's security-relevant state, with recommendations.

    Covers engines and signature freshness, rule packs, recurring scans, the
    most recent scan, quarantine encryption, network use, the audit trail, data
    retention and secret storage. Useful as a quick health check, and as
    evidence for a security review (see docs/COMPLIANCE.md).
    """
    rep = posture_report(Config.load())
    if json_out:
        typer.echo(_json.dumps(rep, indent=2))
    else:
        table = Table(title=f"Warden {rep['warden_version']} posture - {rep['host']}")
        table.add_column("Check", style="bold")
        table.add_column("Status", no_wrap=True)
        table.add_column("Detail", overflow="fold")
        label = {"ok": "[green]OK[/]", "attention": "[yellow]ATTENTION[/]", "info": "[cyan]INFO[/]"}
        for c in rep["checks"]:
            detail = _esc(c["detail"]) + (f"\n[dim]-> {_esc(c['advice'])}[/]" if c["advice"] else "")
            table.add_row(_esc(c["title"]), label.get(c["status"], _esc(c["status"])), detail)
        console.print(table)
        n = rep["attention"]
        console.print(f"[yellow]{n} item(s) need attention.[/]" if n else "[green]Nothing needs attention.[/]")
    raise typer.Exit(1 if strict and rep["attention"] else 0)


def _launched_by_double_click() -> bool:
    """True when the Windows console was created just for us (Explorer launch),
    rather than inherited from a terminal the user is typing in."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        # If we're the only process attached to the console, nobody launched us
        # from an existing shell -> it was a double-click.
        buf = (ctypes.c_uint * 4)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(buf, 4)
        return n <= 1
    except Exception:  # noqa: BLE001
        return False


def main():
    # A double-clicked CLI just flashes a console and closes, which looks broken.
    # When the packaged exe is opened from Explorer with no arguments, launch the
    # dashboard instead. In a terminal (or with args) it behaves as a normal CLI.
    double_click = (
        getattr(sys, "frozen", False)
        and len(sys.argv) == 1
        and _launched_by_double_click()
    )
    if double_click:
        sys.argv.append("gui")
    try:
        app()
    except SystemExit as exc:
        # Keep the window open on an error so a double-click user can read it.
        if double_click and exc.code not in (0, None):
            try:
                input("\nPress Enter to close…")
            except EOFError:
                pass
        raise


if __name__ == "__main__":
    main()
