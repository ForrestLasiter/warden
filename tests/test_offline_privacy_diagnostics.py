"""Offline mode, the privacy report, ClamAV freshness and scheduler diagnostics."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from warden import net, scheduler
from warden.cli import app
from warden.config import Config
from warden.engines import clamav
from warden.history import History
from warden.models import ScanReport
from warden.reputation import OnlineReputation
from warden.scanner import Scanner
from warden.scheduler import Scheduler, ScheduleSpec

runner = CliRunner()


@pytest.fixture(autouse=True)
def _reset_offline():
    net.set_offline(False)
    yield
    net.set_offline(False)


@pytest.fixture()
def no_network(monkeypatch):
    """Fail the test if anything reaches for the network."""
    calls = []

    def boom(*a, **kw):
        calls.append(a)
        raise AssertionError("network was used")

    if net.httpx is not None:
        monkeypatch.setattr(net.httpx, "get", boom)
        monkeypatch.setattr(net.httpx, "stream", boom)
    return calls


# -- offline mode --------------------------------------------------------
def test_offline_sources(monkeypatch, tmp_path):
    cfg = Config(data_dir=tmp_path)
    assert net.is_offline(cfg) is False
    monkeypatch.setenv("WARDEN_OFFLINE", "1")
    assert net.is_offline(cfg) is True
    monkeypatch.delenv("WARDEN_OFFLINE")
    cfg.offline = True
    assert net.is_offline(cfg) is True
    cfg.offline = False
    net.set_offline(True)
    assert net.is_offline(cfg) is True


def test_offline_blocks_requests_before_any_socket(no_network):
    net.set_offline(True)
    with pytest.raises(net.OfflineError):
        net.get("https://example.com/")
    with pytest.raises(net.OfflineError):
        net.download("https://example.com/x", max_bytes=10)
    assert no_network == []


def test_plain_http_is_refused(no_network):
    with pytest.raises(net.NetworkError):
        net.get("http://example.com/")
    with pytest.raises(net.NetworkError):
        net.download("ftp://example.com/x", max_bytes=10)
    assert no_network == []


def test_offline_disables_reputation_even_when_enabled(tmp_path, no_network):
    cfg = Config(data_dir=tmp_path)
    cfg.online_hash_lookup = True
    cfg.offline = True
    rep = OnlineReputation(cfg)
    assert rep.available is False and "offline" in rep.status
    assert rep.check("a" * 64, "b" * 40) is None

    scanner = Scanner(cfg)
    assert scanner.hashes._reputation is None
    assert any("offline mode" in a for a in scanner.advisories)
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\x00" * 200)
    report = scanner.scan_path(f)
    assert report.advisories and report.coverage_complete   # advisory, not a coverage gap
    assert no_network == []


def test_cli_offline_flag_overrides_online(home, tmp_path, no_network):
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\x00" * 200)
    res = runner.invoke(app, ["--offline", "scan", str(f), "--online"])
    assert res.exit_code == 0, res.output
    assert "offline mode" in res.output
    assert no_network == []


def test_cli_offline_env_blocks_lookup(home, monkeypatch, no_network):
    monkeypatch.setenv("WARDEN_OFFLINE", "1")
    res = runner.invoke(app, ["lookup", "a" * 64])
    assert res.exit_code == 2 and "Offline mode" in res.output
    assert no_network == []


def test_offline_flag_does_not_leak_between_invocations(home, tmp_path):
    f = tmp_path / "n.txt"
    f.write_text("x")
    runner.invoke(app, ["--offline", "scan", str(f)])
    assert net.is_offline() is True
    runner.invoke(app, ["scan", str(f)])
    assert net.is_offline() is False


def test_default_scan_makes_no_network_calls(home, tmp_path, no_network):
    f = tmp_path / "tool.exe"
    f.write_bytes(b"MZ" + b"\x00" * 200)
    res = runner.invoke(app, ["scan", str(f)])
    assert res.exit_code == 0, res.output
    assert no_network == []


# -- privacy -------------------------------------------------------------
def test_privacy_report_json(home, tmp_path):
    History().save(ScanReport(root=str(tmp_path)), kind="scan")
    res = runner.invoke(app, ["privacy", "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["telemetry"].startswith("none")
    assert data["network"]["online_hash_lookup_enabled"] is False
    assert data["network"]["offline_mode"] is False
    stored = data["stored_on_this_computer"]
    assert stored["history_reports"]["count"] == 1
    assert "absolute file paths" in stored["history_reports"]["contains"]
    assert stored["virustotal_key"]["stored"] is False
    assert str(home) in stored["data_dir"]


def test_privacy_reflects_online_and_offline(home, no_network):
    runner.invoke(app, ["config", "set", "online_hash_lookup", "true"])
    data = json.loads(runner.invoke(app, ["privacy", "--json"]).output)
    assert data["network"]["online_hash_lookup_enabled"] is True
    assert data["network"]["provider_in_use"] == "cymru"

    data = json.loads(runner.invoke(app, ["--offline", "privacy", "--json"]).output)
    assert data["network"]["offline_mode"] is True
    assert data["network"]["online_hash_lookup_enabled"] is False
    assert no_network == []


def test_privacy_human_output(home):
    res = runner.invoke(app, ["privacy"])
    assert res.exit_code == 0, res.output
    assert "Telemetry" in res.output and "None." in res.output


# -- ClamAV database freshness ------------------------------------------
def _cvd(version: int, built: float, *, stime: bool = True) -> bytes:
    stamp = datetime.fromtimestamp(built, timezone.utc).strftime("%d %b %Y %H-%M +0000")
    head = f"ClamAV-VDB:{stamp}:{version}:2070000:90:abcd:sig:builder"
    if stime:
        head += f":{int(built)}"
    return head.encode().ljust(512, b" ")


def test_parse_cvd_header_with_and_without_epoch():
    now = time.time()
    fresh = clamav.parse_cvd_header(_cvd(27412, now - 2 * 86400), now=now)
    assert fresh["version"] == 27412 and fresh["signatures"] == 2070000 and fresh["age_days"] == 2
    old = clamav.parse_cvd_header(_cvd(27000, now - 40 * 86400, stime=False), now=now)
    assert old["age_days"] in (39, 40)
    assert clamav.parse_cvd_header(b"not a database") is None
    assert clamav.parse_cvd_header(b"ClamAV-VDB:x:notanumber:y") is None


def test_parse_version_output():
    now = datetime(2026, 10, 4, tzinfo=timezone.utc).timestamp()
    info = clamav.parse_version_output("ClamAV 1.4.1/27412/Mon Sep 28 08:33:02 2026\n", now=now)
    assert info["version"] == 27412 and info["age_days"] == 5
    assert clamav.parse_version_output("ClamAV 1.4.1\n") is None    # no database loaded


def test_find_database_and_staleness(tmp_path):
    (tmp_path / "daily.cvd").write_bytes(_cvd(100, time.time() - 30 * 86400))
    info = clamav.find_database(extra_dirs=(str(tmp_path),))
    assert info["version"] == 100 and info["age_days"] >= 29
    assert "STALE" in clamav.describe_database(info)
    assert "NOT FOUND" in clamav.describe_database(None)


def test_freshness_advisory_paths():
    eng = clamav.ClamAVEngine(enabled=False)
    assert eng.freshness_advisory() is None          # ClamAV not in use: nothing to say

    eng._enabled = True
    eng._standalone = "/usr/bin/clamscan"            # pretend it is installed
    eng._db_checked = True
    eng._db = None
    assert "could not be found" in eng.freshness_advisory()
    eng._db = {"version": 5, "age_days": 30}
    assert "30 days old" in eng.freshness_advisory()
    assert "STALE" in eng.status
    eng._db = {"version": 5, "age_days": 1}
    assert eng.freshness_advisory() is None


# -- scheduler diagnostics ----------------------------------------------
@pytest.fixture()
def sched(tmp_path, monkeypatch):
    s = Scheduler(Config(data_dir=tmp_path / "data"))
    monkeypatch.setattr(scheduler, "_cron_daemon_running", lambda: True)
    return s


def _register(s: Scheduler, spec: ScheduleSpec) -> None:
    s._save(s._load() + [spec.to_dict()])


def test_doctor_cron_states(sched, tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler, "IS_WINDOWS", False)
    target = tmp_path / "docs"
    target.mkdir()
    good = ScheduleSpec(name="good", kind="scan", target=str(target))
    gone = ScheduleSpec(name="gone", kind="sweep")
    edited = ScheduleSpec(name="edited", kind="sweep")
    lost = ScheduleSpec(name="lost", kind="scan", target=str(tmp_path / "deleted"))
    for spec in (good, gone, edited, lost):
        _register(sched, spec)
    crontab = "\n".join([
        "0 1 * * * /usr/bin/other",
        scheduler._cron_line(good.to_dict()),
        "5 5 * * * /somewhere/else/warden sweep  # warden:edited",
        scheduler._cron_line(lost.to_dict()),
        "0 0 * * * /x/warden sweep  # warden:stray",
    ])
    monkeypatch.setattr(scheduler, "_cron_current", lambda: (crontab, None))

    diagnoses, general = sched.diagnose()
    by = {d.name: d for d in diagnoses}
    assert by["good"].ok and by["good"].info["state"] == "installed"
    assert any("no crontab entry" in p for p in by["gone"].problems)
    assert any("differs" in p for p in by["edited"].problems)
    assert any("target no longer exists" in p for p in by["lost"].problems)
    assert any("orphaned OS task 'stray'" in g for g in general)


def test_doctor_reports_stopped_cron_daemon(sched, monkeypatch):
    monkeypatch.setattr(scheduler, "IS_WINDOWS", False)
    monkeypatch.setattr(scheduler.sys, "platform", "linux")
    monkeypatch.setattr(scheduler, "_cron_daemon_running", lambda: False)
    monkeypatch.setattr(scheduler, "_cron_current", lambda: ("", None))
    _register(sched, ScheduleSpec(name="a", kind="sweep"))
    _, general = sched.diagnose()
    assert any("cron daemon" in g for g in general)


def test_doctor_windows_states(sched, monkeypatch):
    monkeypatch.setattr(scheduler, "IS_WINDOWS", True)
    ok = ScheduleSpec(name="ok", kind="sweep")
    missing = ScheduleSpec(name="missing", kind="sweep")
    moved = ScheduleSpec(name="moved", kind="sweep")
    failed = ScheduleSpec(name="failed", kind="sweep")
    for spec in (ok, missing, moved, failed):
        _register(sched, spec)
    exe = ok.command_args()[0]
    tasks = {
        "ok": {"State": "Ready", "Execute": exe, "LastTaskResult": 1, "NextRunTime": "2026-10-05 03:00"},
        "moved": {"State": "Disabled", "Execute": r"C:\old\warden.exe", "LastTaskResult": 0},
        "failed": {"State": "Ready", "Execute": f'"{exe}"', "LastTaskResult": 0x80070002},
    }
    monkeypatch.setattr(scheduler, "_win_task_info", lambda name: tasks.get(name))
    monkeypatch.setattr(scheduler, "_win_list_tasks", lambda: ["ok", "moved", "failed", "ghost"])

    diagnoses, general = sched.diagnose()
    by = {d.name: d for d in diagnoses}
    assert by["ok"].ok                                   # exit 1 = threats found, not a failure
    assert "THREATS FOUND" in by["ok"].info["last_result"]
    assert any("no task" in p for p in by["missing"].problems)
    assert any("disabled" in p for p in by["moved"].problems)
    assert any("not this Warden install" in p for p in by["moved"].problems)
    assert any("failed to run" in p for p in by["failed"].problems)
    assert any("ghost" in g for g in general)


def test_doctor_flags_schedule_that_never_ran(sched, monkeypatch):
    monkeypatch.setattr(scheduler, "IS_WINDOWS", False)
    long_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    spec = ScheduleSpec(name="quiet", kind="sweep", frequency="daily", created=long_ago)
    _register(sched, spec)
    monkeypatch.setattr(scheduler, "_cron_current",
                        lambda: (scheduler._cron_line(spec.to_dict()), None))
    (d,), _ = sched.diagnose()
    assert any("no sweep has been recorded" in p for p in d.problems)

    History(sched.config).save(ScanReport(root="<system-sweep>", finished=datetime.now(timezone.utc).isoformat()),
                               kind="sweep")
    (d,), _ = sched.diagnose()
    assert d.ok and d.info["last_recorded_run"]


def test_schedule_created_timestamp_and_legacy_registry(sched, monkeypatch):
    monkeypatch.setattr(sched, "_install_os_task", lambda spec: "ok")
    sched.add(ScheduleSpec(name="fresh", kind="sweep"))
    assert sched.list()[0].created
    # An entry written by an older Warden (no 'created') still loads.
    sched._save([{"name": "old", "kind": "sweep", "frequency": "daily", "time": "03:00"}])
    assert sched.list()[0].created == ""


def test_schedule_doctor_cli(home, monkeypatch):
    monkeypatch.setattr(scheduler, "_win_list_tasks", lambda: [])
    monkeypatch.setattr(scheduler, "_cron_current", lambda: ("", None))
    res = runner.invoke(app, ["schedule", "doctor"])
    assert res.exit_code == 0 and "No schedules" in res.output

    s = Scheduler()
    _register(s, ScheduleSpec(name="nightly", kind="sweep"))
    monkeypatch.setattr(scheduler, "_win_task_info", lambda name: None)
    monkeypatch.setattr(scheduler, "_cron_daemon_running", lambda: True)
    res = runner.invoke(app, ["schedule", "doctor", "--json"])
    assert res.exit_code == 1
    data = json.loads(res.output)
    assert data["ok"] is False and data["schedules"][0]["name"] == "nightly"
    assert runner.invoke(app, ["schedule", "doctor"]).exit_code == 1
