"""End-to-end CLI tests (Typer's runner; isolated ~/.warden)."""

from __future__ import annotations

import json
import sys

from _builders import make_elf64, make_zip
from typer.testing import CliRunner

from warden.cli import _esc, app

runner = CliRunner()


def test_esc_neutralizes_markup_and_control_chars():
    assert "\x1b" not in _esc("a\x1b[31mb")
    assert "\n" not in _esc("line1\nline2")
    # Rich would raise MarkupError on an unmatched closing tag if unescaped.
    assert _esc("x[/red]y") == "x\\[/red]y"


def test_scan_clean_file_exits_zero(home, tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    res = runner.invoke(app, ["scan", str(f)])
    assert res.exit_code == 0, res.output
    assert "CLEAN" in res.output


def test_scan_survives_hostile_member_names(home, tmp_path):
    """A crafted archive member name must not crash report rendering."""
    z = tmp_path / "pack.zip"
    z.write_bytes(make_zip({"a[/b]\x1b[2Jc.pdf.exe": b"harmless", "[bold]x[/nope].pdf.exe": b"y"}))
    res = runner.invoke(app, ["scan", str(z)])
    assert res.exception is None or isinstance(res.exception, SystemExit), res.output
    assert res.exit_code == 1                      # double-extension members flagged
    assert "\x1b[2J" not in res.output
    assert "Archives opened" in res.output


def test_scan_no_archives_flag(home, tmp_path):
    z = tmp_path / "pack.zip"
    z.write_bytes(make_zip({"invoice.pdf.exe": b"harmless"}))
    res = runner.invoke(app, ["scan", str(z), "--no-archives"])
    assert res.exit_code == 0, res.output


def test_scan_json_report_has_meta_and_coverage(home, tmp_path):
    f = tmp_path / "tool"
    f.write_bytes(make_elf64(rwx=True))
    out = tmp_path / "r.json"
    res = runner.invoke(app, ["scan", str(f), "--json", str(out)])
    assert res.exit_code == 0, res.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["results"][0]["meta"]["binary"]["format"] == "elf"
    assert "archives_opened" in data["coverage"]


def test_inspect_json(home, tmp_path):
    res = runner.invoke(app, ["inspect", sys.executable, "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert len(data["sha256"]) == 64
    assert data["binary"]["format"] in ("pe", "elf", "macho")


def test_inspect_archive_listing(home, tmp_path):
    z = tmp_path / "a.zip"
    z.write_bytes(make_zip({"one.txt": b"1", "two.txt": b"22"}))
    res = runner.invoke(app, ["inspect", str(z)])
    assert res.exit_code == 0, res.output
    assert "2 member(s)" in res.output and "one.txt" in res.output


def test_inspect_missing_file(home, tmp_path):
    assert runner.invoke(app, ["inspect", str(tmp_path / "nope")]).exit_code == 2


def test_config_toggles_new_settings(home):
    assert runner.invoke(app, ["config", "set", "scan_archives", "false"]).exit_code == 0
    res = runner.invoke(app, ["config", "get", "scan_archives"])
    assert "False" in res.output
