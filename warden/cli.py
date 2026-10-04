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

import json as _json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .config import Config
from .history import History
from .models import FileResult, ScanReport, Severity
from .quarantine import Quarantine, QuarantineError
from .scanner import Scanner
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
    if not scanner.clamav.available():
        console.print("[dim]Tip: install ClamAV + run freshclam for millions more signatures (optional).[/]")


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
    scanner = Scanner(cfg)
    console.print(Panel.fit(
        f"[bold]Warden[/] scanning [cyan]{target}[/]\n"
        f"engines: {', '.join(scanner.active_engines()) or 'none!'}",
        border_style="blue",
    ))

    threats: list[FileResult] = []

    with Progress(
        SpinnerColumn(),
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
            progress.update(task, count=count, description=f"scanning {Path(result.path).name[:40]}")
            if result.is_threat:
                threats.append(result)

        report = scanner.scan_path(target, recursive=recursive, progress=on_file)

    _print_report(report, threshold=threshold, quiet=quiet)

    if json_out:
        Path(json_out).write_text(_json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]JSON report written to {json_out}[/]")

    if save:
        entry = History().save(report, kind="scan")
        console.print(f"[dim]Saved to history as {entry.id}[/]")

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
        SpinnerColumn(),
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
            progress.update(task, count=count, description=f"scanning {Path(result.path).name[:40]}")
            if result.is_threat:
                threats.append(result)

        report, categories = sweeper.run(quick=quick, progress=on_file)

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

    if save:
        entry = History().save(report, kind="sweep")
        console.print(f"[dim]Saved to history as {entry.id}[/]")

    # Recompute threats from the report (location heuristic may have added some).
    flagged = [r for r in report.results if r.is_threat]
    if quarantine and flagged:
        _do_quarantine(flagged)

    raise typer.Exit(_scan_exit_code(report))


def _print_report(report: ScanReport, *, threshold: Severity, quiet: bool):
    shown = 0
    for r in report.results:
        if r.error:
            if not quiet:
                console.print(f"[dim]! {Path(r.path).name}: {r.error}[/]")
            continue
        if r.verdict < threshold or not r.findings:
            continue
        shown += 1
        header = f"[{_style(r.verdict)}] {r.verdict.label:8}[/] {r.path}"
        console.print(header)
        for f in r.findings:
            if f.severity < threshold:
                continue
            console.print(f"    [{_style(f.severity)}]-[/] ({f.engine}) [bold]{f.name}[/]: {f.description}")

    # A degraded scan (e.g. a YARA ruleset that failed to compile) is not "clean".
    for w in report.warnings:
        console.print(f"[yellow]! engine unavailable:[/] {w} [dim](coverage reduced)[/]")

    # Surface files an engine could not finish on - these are 'unknown', NOT clean.
    unknown = report.unknown
    if unknown and not quiet:
        for r in unknown:
            console.print(f"[yellow]? UNKNOWN [/] {r.path} [dim](an engine could not scan this file)[/]")

    # Coverage gaps: paths we couldn't read at all.
    if report.unreadable and not quiet:
        shown_u = report.unreadable[:15]
        for p in shown_u:
            console.print(f"[yellow]! unreadable:[/] {p}")
        if len(report.unreadable) > len(shown_u):
            console.print(f"[dim]  …and {len(report.unreadable) - len(shown_u)} more unreadable path(s)[/]")

    dur = report.duration_seconds or 0.0
    summary = Table.grid(padding=(0, 2))
    summary.add_row("Files scanned:", str(report.files_scanned))
    summary.add_row("Skipped by type:", str(report.skipped_ext))
    summary.add_row("Skipped (too large):", str(report.skipped_oversized))
    summary.add_row("Threats (medium+):", f"[red]{len(report.threats)}[/]" if report.threats else "0")
    summary.add_row("Unknown (engine error):", f"[yellow]{len(unknown)}[/]" if unknown else "0")
    summary.add_row("Unreadable paths:", f"[yellow]{len(report.unreadable)}[/]" if report.unreadable else "0")
    summary.add_row("Findings shown:", str(shown))
    summary.add_row("Read/access errors:", str(report.errors))
    summary.add_row("Duration:", f"{dur:.1f}s")
    if report.threats:
        verdict_color, title = "red", "THREATS FOUND"
    elif not report.coverage_complete:
        verdict_color, title = "yellow", "INCOMPLETE — COVERAGE GAPS"
    else:
        verdict_color, title = "green", "CLEAN"
    console.print(Panel(summary, title=f"[{verdict_color}]{title}[/]", border_style=verdict_color))


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
        console.print(f"  [{_style(r.verdict)}]{r.verdict.label}[/] {r.path}")
    if not typer.confirm("Quarantine all flagged files now?", default=False):
        console.print("[dim]Skipped quarantine.[/]")
        return
    q = Quarantine()
    for r in threats:
        try:
            entry = q.quarantine_file(r)
            console.print(f"  [green]quarantined[/] {r.path}  (id {entry.id})")
        except QuarantineError as exc:
            console.print(f"  [red]failed[/] {r.path}: {exc}")


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
    table.add_column("ID", style="bold")
    table.add_column("Verdict")
    table.add_column("When")
    table.add_column("Original path")
    table.add_column("Status")
    for e in entries:
        status_txt = "[yellow]restored[/]" if e.restored else "[red]isolated[/]"
        table.add_row(e.id, e.verdict, e.quarantined_at.split("T")[0], e.original_path, status_txt)
    console.print(table)


@quarantine_app.command("restore")
def quarantine_restore(
    entry_id: str = typer.Argument(..., help="Quarantine entry ID (from 'quarantine list')."),
    dest: str | None = typer.Option(None, "--to", help="Restore to this path instead of the original."),
):
    """Restore a quarantined file."""
    q = Quarantine()
    try:
        out = q.restore(entry_id, Path(dest) if dest else None)
    except QuarantineError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Restored[/] to {out}")


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
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)
    console.print(f"[green]Deleted[/] {entry_id}")


@app.command()
def lookup(
    target: str = typer.Argument(..., help="A file path, or a SHA-256 / SHA-1 hash."),
):
    """Check a file or hash against online reputation (Team Cymru / VirusTotal)."""
    from .engines.base import ScanContext
    from .reputation import OnlineReputation

    cfg = Config.load()
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
        f"For millions of ClamAV signatures, install ClamAV and run [bold]freshclam[/].",
        title="Adding rules & signatures",
        border_style="blue",
    ))


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
    table.add_column("ID", style="bold")
    table.add_column("Kind")
    table.add_column("When (UTC)")
    table.add_column("Files", justify="right")
    table.add_column("Threats", justify="right")
    table.add_column("Target")
    for e in entries:
        threat_cell = f"[red]{e.threats}[/]" if e.threats else "0"
        table.add_row(e.id, e.kind, e.when.replace("T", " ")[:19], str(e.files_scanned), threat_cell, e.root)
    console.print(table)


@history_app.command("show")
def history_show(entry_id: str = typer.Argument(..., help="History ID (or prefix).")):
    """Show the threats from a saved report."""
    data = History().load(entry_id)
    if data is None:
        console.print(f"[red]No history entry matching[/] {entry_id}")
        raise typer.Exit(2)
    console.print(f"[bold]{data.get('id')}[/]  kind={data.get('kind')}  target={data.get('root')}")
    console.print(f"files scanned: {data.get('files_scanned')}  threats: {data.get('threats')}  "
                  f"duration: {data.get('duration_seconds')}s")
    threats = [r for r in data.get("results", []) if r.get("verdict", 0) >= int(Severity.MEDIUM)]
    if not threats:
        console.print("[green]No threats in this report.[/]")
        return
    for r in threats:
        sev = Severity(r["verdict"])
        console.print(f"\n[{_style(sev)}] {sev.label}[/] {r['path']}")
        for f in r.get("findings", []):
            fsev = Severity(f["severity"])
            console.print(f"    [{_style(fsev)}]-[/] ({f['engine']}) [bold]{f['name']}[/]: {f['description']}")


@history_app.command("prune")
def history_prune(keep: int = typer.Option(50, "--keep", help="How many recent reports to keep.")):
    """Delete old history, keeping the most recent N."""
    removed = History().prune(keep=keep)
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
        table.add_row(s.name, s.kind, s.frequency, s.time if s.frequency != "hourly" else "-", s.target or "-")
    console.print(table)


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
    "use_clamav": (bool, "Use ClamAV if its binaries are on PATH."),
    "follow_symlinks": (bool, "Follow symlinks when walking folders."),
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
    setattr(cfg, key, coerced)
    cfg.save()
    shown = _mask(str(coerced)) if key in _SECRET_FIELDS else str(coerced)
    console.print(f"[green]Set[/] {key} = {shown}")


@config_app.command("unset")
def config_unset(key: str = typer.Argument(..., help="Setting name to clear/reset.")):
    """Reset a setting to its default."""
    if key not in _CONFIG_FIELDS:
        console.print(f"[red]Unknown setting[/] '{key}'. Options: {', '.join(_CONFIG_FIELDS)}")
        raise typer.Exit(2)
    default = getattr(Config(), key)
    cfg = Config.load()
    setattr(cfg, key, default)
    cfg.save()
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
    console.print(f"[green]Saved VirusTotal key[/] ({_mask(key)}) to the OS secret store "
                  f"([bold]{_secrets.backend_name()}[/]).")
    if enable:
        console.print("[dim]Online reputation is now enabled by default. Disable with:[/] warden config set online_hash_lookup false")


@config_app.command("path")
def config_path():
    """Print the path to the config file."""
    console.print(str(Config.load().config_path))


def _launched_by_double_click() -> bool:
    """True when the Windows console was created just for us (Explorer launch),
    rather than inherited from a terminal the user is typing in."""
    if os.name != "nt":
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
