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
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from . import __version__
from .config import Config
from .models import FileResult, Severity, ScanReport
from .scanner import Scanner
from .quarantine import Quarantine, QuarantineError

app = typer.Typer(
    add_completion=False,
    help="Warden - open-source malware scanner (YARA + heuristics + hashes + optional ClamAV).",
    no_args_is_help=True,
)
quarantine_app = typer.Typer(help="Manage quarantined files.", no_args_is_help=True)
app.add_typer(quarantine_app, name="quarantine")

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
    json_out: Optional[str] = typer.Option(None, "--json", help="Write full report as JSON to this path."),
    quiet: bool = typer.Option(False, "--quiet", help="Only print the summary and threats."),
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

    scanner = Scanner()
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

    if quarantine and threats:
        _do_quarantine(threats)

    # Exit code reflects the worst verdict, useful for scripts/scheduling.
    worst = max((r.verdict for r in report.results), default=Severity.CLEAN)
    raise typer.Exit(1 if worst >= Severity.MEDIUM else 0)


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

    dur = report.duration_seconds or 0.0
    summary = Table.grid(padding=(0, 2))
    summary.add_row("Files scanned:", str(report.files_scanned))
    summary.add_row("Skipped (size/type):", str(report.files_skipped))
    summary.add_row("Threats (medium+):", f"[red]{len(report.threats)}[/]" if report.threats else "0")
    summary.add_row("Findings shown:", str(shown))
    summary.add_row("Errors:", str(report.errors))
    summary.add_row("Duration:", f"{dur:.1f}s")
    verdict_color = "red" if report.threats else "green"
    title = "THREATS FOUND" if report.threats else "CLEAN"
    console.print(Panel(summary, title=f"[{verdict_color}]{title}[/]", border_style=verdict_color))


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
    dest: Optional[str] = typer.Option(None, "--to", help="Restore to this path instead of the original."),
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


def main():
    app()


if __name__ == "__main__":
    main()
