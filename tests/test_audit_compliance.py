"""Audit trail, data-retention, license notices, posture report and
crash-proof console output."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from warden import audit, notices, rulepacks, scheduler, secrets
from warden.audit import AuditError, AuditLog
from warden.cli import _spinner_name, app
from warden.config import Config
from warden.history import History
from warden.models import FileResult, Finding, ScanReport, Severity
from warden.quarantine import Quarantine, QuarantineError
from warden.rulepacks import RulePackManager
from warden.scheduler import Scheduler, ScheduleSpec

runner = CliRunner()


def _cfg(tmp_path, **kw) -> Config:
    cfg = Config(data_dir=tmp_path / "data")
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def _events(cfg) -> list[str]:
    return [e["event"] for e in AuditLog(cfg).entries()]


def _lines(log: AuditLog) -> list[str]:
    return log.path.read_text(encoding="utf-8").splitlines()


def _backdate(log: AuditLog, index: int, days: float) -> None:
    """Rewrite the whole log so entry ``index`` and earlier are ``days`` old,
    with a consistent chain (what a legitimately old log looks like)."""
    entries = [json.loads(line) for line in _lines(log)]
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    prev = audit.GENESIS
    out = []
    for i, e in enumerate(entries):
        body = {k: e[k] for k in ("seq", "ts", "event", "actor", "details")}
        if i <= index:
            body["ts"] = old
        body["prev"] = prev
        prev = audit._digest(prev, body)
        out.append(json.dumps({**body, "hash": prev}, separators=(",", ":")))
    log.path.write_text("\n".join(out) + "\n", encoding="utf-8")


# -- the chain -----------------------------------------------------------
def test_entries_chain_and_verify(tmp_path):
    log = AuditLog(_cfg(tmp_path))
    first = log.record("test.one", path="/a/b", n=1)
    second = log.record("test.two", note="x")
    assert first["seq"] == 1 and first["prev"] == audit.GENESIS
    assert second["seq"] == 2 and second["prev"] == first["hash"]
    assert first["actor"]["user"] and first["actor"]["host"]

    res = log.verify()
    assert res["ok"] and res["entries"] == 2 and res["head_hash"] == second["hash"]
    assert [e["event"] for e in log.entries()] == ["test.one", "test.two"]
    assert [e["event"] for e in log.entries(event="test.t")] == ["test.two"]
    assert len(log.entries(limit=1)) == 1


@pytest.mark.parametrize("tamper", ["edit", "delete-middle", "delete-first", "reorder", "insert", "garbage"])
def test_tampering_is_detected(tmp_path, tamper):
    log = AuditLog(_cfg(tmp_path))
    for i in range(5):
        log.record("quarantine.delete", id=f"item{i}", path=f"/files/{i}")
    lines = _lines(log)
    if tamper == "edit":
        lines[2] = lines[2].replace("/files/2", "/files/9")
    elif tamper == "delete-middle":
        del lines[2]
    elif tamper == "delete-first":
        del lines[0]
    elif tamper == "reorder":
        lines[1], lines[3] = lines[3], lines[1]
    elif tamper == "insert":
        forged = json.loads(lines[1])
        forged["details"] = {"id": "forged"}
        lines.insert(2, json.dumps(forged))
    elif tamper == "garbage":
        lines[3] = "{ not json"
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = log.verify()
    assert not res["ok"] and res["problems"]


def test_removing_the_newest_entries_changes_the_head_hash(tmp_path):
    """Truncating the tail leaves a valid shorter chain - which is exactly why
    'verify' prints the head hash to record elsewhere."""
    log = AuditLog(_cfg(tmp_path))
    for i in range(4):
        log.record("x", i=i)
    head = log.verify()["head_hash"]
    log.path.write_text("\n".join(_lines(log)[:2]) + "\n", encoding="utf-8")
    res = log.verify()
    assert res["ok"] and res["entries"] == 2 and res["head_hash"] != head


def test_appending_after_damage_still_records_and_pinpoints_it(tmp_path):
    log = AuditLog(_cfg(tmp_path))
    log.record("a")
    with open(log.path, "ab") as fh:
        fh.write(b"\x00\xffcorrupt tail\n")
    assert log.record("b") is not None            # new events are never lost
    res = log.verify()
    assert not res["ok"] and any("line 2" in p for p in res["problems"])
    assert [e["event"] for e in log.entries()] == ["a", "b"]


def test_disabled_log_writes_nothing(tmp_path):
    cfg = _cfg(tmp_path, audit_log=False)
    log = AuditLog(cfg)
    assert log.record("x") is None
    assert not log.path.exists()
    assert log.verify() == {**log.verify(), "ok": True, "entries": 0, "enabled": False}


def test_record_never_raises_when_the_log_is_unwritable(tmp_path, monkeypatch, capsys):
    log = AuditLog(_cfg(tmp_path))
    monkeypatch.setattr(audit, "_warned", set())

    def boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(audit.os, "open", boom)
    assert log.record("x") is None                # the operation being audited goes on
    assert "could not write the audit log" in capsys.readouterr().err


def test_details_are_sanitized_and_bounded(tmp_path):
    log = AuditLog(_cfg(tmp_path))
    entry = log.record("x", path="evil\x1b[31m\nname", big="A" * 10_000,
                       nested={"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}, many=list(range(500)),
                       obj=Path("/p"))
    d = entry["details"]
    assert "\x1b" not in d["path"] and "\n" not in d["path"]
    assert len(d["big"]) == 2000 and len(d["many"]) == 40
    assert isinstance(d["obj"], str)
    assert len(_lines(log)[0]) < 64 * 1024 and log.verify()["ok"]


def test_concurrent_writers_keep_one_intact_chain(tmp_path):
    cfg = _cfg(tmp_path)

    def work(n):
        for i in range(15):
            AuditLog(cfg).record("thread", n=n, i=i)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    res = AuditLog(cfg).verify()
    assert res["ok"] and res["entries"] == 90
    assert [e["seq"] for e in AuditLog(cfg).entries()] == list(range(1, 91))


# -- prune / export ------------------------------------------------------
def test_prune_keeps_the_chain_verifiable_and_records_itself(tmp_path):
    log = AuditLog(_cfg(tmp_path))
    for i in range(6):
        log.record("x", i=i)
    _backdate(log, 2, days=400)                  # entries 1-3 are old
    assert log.verify()["ok"]

    assert log.prune(365) == 3
    entries = log.entries()
    assert entries[0]["event"] == "audit.pruned" and entries[0]["details"]["removed_entries"] == 3
    assert [e["seq"] for e in entries] == [3, 4, 5, 6]            # numbering continues
    assert log.verify()["ok"]

    log.record("after")
    assert log.verify()["ok"] and log.entries()[-1]["seq"] == 7
    assert log.prune(365) == 0                                    # nothing else is old

    # Tampering with a kept entry after a prune is still caught.
    lines = _lines(log)
    lines[1] = lines[1].replace('"i":3', '"i":33')
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not log.verify()["ok"]


def test_prune_everything_then_keep_logging(tmp_path):
    log = AuditLog(_cfg(tmp_path))
    for i in range(3):
        log.record("x", i=i)
    _backdate(log, 2, days=10)
    assert log.prune(0) == 3
    assert [e["event"] for e in log.entries()] == ["audit.pruned"]
    log.record("fresh")
    res = log.verify()
    assert res["ok"] and res["entries"] == 2 and log.entries()[-1]["seq"] == 4
    with pytest.raises(AuditError):
        log.prune(-1)


def test_export_copies_and_refuses_to_overwrite(tmp_path):
    log = AuditLog(_cfg(tmp_path))
    log.record("a")
    log.record("b")
    out = tmp_path / "evidence.jsonl"
    res = log.export(out)
    assert res["ok"] and res["entries"] == 2
    assert len(out.read_text(encoding="utf-8").splitlines()) == 2
    with pytest.raises(AuditError):
        log.export(out)
    assert log.entries()[-1]["event"] == "audit.export"           # the export is itself on record


# -- what gets recorded --------------------------------------------------
def _victim(tmp_path: Path, name: str, data: bytes) -> FileResult:
    f = tmp_path / name
    f.write_bytes(data)
    return FileResult(path=str(f), size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                      findings=[Finding("yara", "T", Severity.HIGH)])


def test_quarantine_lifecycle_is_audited(tmp_path):
    cfg = _cfg(tmp_path)
    q = Quarantine(cfg)
    a = q.quarantine_file(_victim(tmp_path, "a.bin", b"aaa"))
    b = q.quarantine_file(_victim(tmp_path, "b.bin", b"bbb"))
    q.rescan(a.id)
    bundle = q.export(a.id, tmp_path / "a.wq")
    q.restore(a.id)
    q.delete(b.id)
    imported = q.import_bundle(bundle)
    q.purge(everything=True, dry_run=True)        # a dry run deletes nothing: no event
    q.purge(everything=True)

    events = _events(cfg)
    assert events == ["quarantine.add", "quarantine.add", "quarantine.rescan", "quarantine.export",
                      "quarantine.restore", "quarantine.delete", "quarantine.import",
                      "quarantine.delete", "quarantine.delete"]
    entries = AuditLog(cfg).entries()
    add = entries[0]["details"]
    assert add["id"] == a.id and add["sha256"] == a.sha256 and add["path"].endswith("a.bin")
    assert entries[4]["details"]["restored_to"].endswith("a.bin")
    assert entries[-1]["details"]["reason"] == "purge"
    assert imported.id in {e["details"]["id"] for e in entries}
    assert AuditLog(cfg).verify()["ok"]


def test_failed_actions_leave_no_success_event(tmp_path):
    cfg = _cfg(tmp_path)
    q = Quarantine(cfg)
    with pytest.raises(QuarantineError):
        q.delete("0123456789abcdef")
    with pytest.raises(QuarantineError):
        q.restore("0123456789abcdef")
    assert _events(cfg) == []


def test_rule_pack_and_trust_changes_are_audited(tmp_path):
    cfg = _cfg(tmp_path)
    mgr = RulePackManager(cfg)
    priv, pub = rulepacks.generate_keypair()
    import base64
    kid = mgr.trust(base64.b64encode(pub).decode(), "Corp")
    src = tmp_path / "src"
    src.mkdir()
    (src / "r.yar").write_text('rule R { strings: $a = "zzz-marker" condition: $a }')
    for v in (1, 2):
        pack = rulepacks.build_pack(src, "corp", v)
        mgr.install(pack, rulepacks.sign_pack(pack, priv))
    mgr.rollback("corp")
    mgr.remove("corp")
    mgr.untrust(kid)
    assert _events(cfg) == ["rules.trust", "rules.install", "rules.install", "rules.rollback",
                            "rules.remove", "rules.untrust"]
    install = AuditLog(cfg).entries()[2]["details"]
    assert install["version"] == 2 and install["previous_version"] == 1 and install["signed"] is True
    assert install["key_id"] == kid


def test_schedule_changes_are_audited(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    s = Scheduler(cfg)
    monkeypatch.setattr(s, "_install_os_task", lambda spec: "ok")
    monkeypatch.setattr(s, "_remove_os_task", lambda name: None)
    s.add(ScheduleSpec(name="nightly", kind="sweep"))
    s.remove("nightly")
    with pytest.raises(scheduler.SchedulerError):
        s.remove("nightly")
    assert _events(cfg) == ["schedule.add", "schedule.remove"]


def test_cli_scan_config_and_secrets(home, tmp_path, monkeypatch):
    store: dict[str, str] = {}
    monkeypatch.setattr(secrets, "load_secret", lambda name: store.get(name))
    monkeypatch.setattr(secrets, "store_secret", lambda name, value: store.__setitem__(name, value))
    f = tmp_path / "invoice.pdf.exe"
    f.write_bytes(b"x")
    assert runner.invoke(app, ["scan", str(f), "--save"]).exit_code == 1
    assert runner.invoke(app, ["config", "set", "scan_archives", "false"]).exit_code == 0
    assert runner.invoke(app, ["config", "unset", "scan_archives"]).exit_code == 0
    assert runner.invoke(app, ["config", "set-vt-key", "SUPER-SECRET-KEY-123", "--no-enable"]).exit_code == 0

    log = AuditLog()
    entries = log.entries()
    assert [e["event"] for e in entries] == ["scan.completed", "config.set", "config.set", "config.set"]
    scan = entries[0]["details"]
    assert scan["outcome"] == "threats" and scan["threats"] == 1 and scan["exit_code"] == 1
    assert scan["source"] == "cli" and scan["history_id"] and scan["online_lookups"] is False
    assert entries[1]["details"] == {"setting": "scan_archives", "value": False, "previous": True}
    assert entries[2]["details"]["reset"] is True
    # The secret itself must never reach the audit trail.
    assert "SUPER-SECRET-KEY-123" not in log.path.read_text(encoding="utf-8")
    assert entries[3]["details"]["setting"] == "virustotal_api_key"


def test_switching_the_audit_log_off_is_the_last_thing_recorded(home):
    assert runner.invoke(app, ["config", "set", "audit_log", "false"]).exit_code == 0
    assert runner.invoke(app, ["config", "set", "scan_archives", "false"]).exit_code == 0   # not recorded
    entries = AuditLog().entries()
    assert len(entries) == 1
    assert entries[0]["details"] == {"setting": "audit_log", "value": False, "previous": True}
    assert runner.invoke(app, ["config", "set", "audit_log", "true"]).exit_code == 0
    assert AuditLog().entries()[-1]["details"]["value"] is True


def test_config_set_reports_clamped_values(home):
    res = runner.invoke(app, ["config", "set", "history_retention_days", "999999"])
    assert res.exit_code == 0 and "outside the allowed range" in res.output
    assert Config.load().history_retention_days == 36500


def test_audit_cli(home, tmp_path):
    assert "No audit entries" in runner.invoke(app, ["audit", "show"]).output
    runner.invoke(app, ["config", "set", "scan_archives", "false"])
    runner.invoke(app, ["config", "set", "scan_archives", "true"])
    res = runner.invoke(app, ["audit", "show", "--json", "--event", "config"])
    assert res.exit_code == 0 and len(res.output.strip().splitlines()) == 2
    assert json.loads(res.output.splitlines()[0])["event"] == "config.set"
    assert runner.invoke(app, ["audit", "show", "--since", "nonsense"]).exit_code == 2

    res = runner.invoke(app, ["audit", "verify", "--json"])
    assert res.exit_code == 0 and json.loads(res.output)["ok"] is True
    out = tmp_path / "audit.jsonl"
    assert runner.invoke(app, ["audit", "export", str(out)]).exit_code == 0 and out.exists()
    assert runner.invoke(app, ["audit", "export", str(out)]).exit_code == 2

    log = AuditLog()
    lines = _lines(log)
    lines[0] = lines[0].replace("scan_archives", "follow_symlinks")
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = runner.invoke(app, ["audit", "verify"])
    assert res.exit_code == 1 and "FAILED" in res.output

    assert "Cancelled" in runner.invoke(app, ["audit", "prune", "--older-than", "30d"], input="n\n").output
    assert runner.invoke(app, ["audit", "prune", "--older-than", "bad", "--yes"]).exit_code == 2
    assert runner.invoke(app, ["audit", "prune", "--older-than", "30d", "--yes"]).exit_code == 0


def test_dashboard_scan_is_audited(home, tmp_path):
    from warden.gui import server as gui
    job = gui.JOBS.create("scan")
    f = tmp_path / "n.txt"
    f.write_text("hello")
    gui._run_scan_job(job, str(f), "low", True)
    entry = AuditLog().entries()[-1]
    assert entry["event"] == "scan.completed" and entry["details"]["source"] == "dashboard"
    assert entry["details"]["outcome"] == "clean" and entry["details"]["history_id"]


# -- history retention ---------------------------------------------------
def _old_report(history: History, days: float, kind: str = "scan") -> Path:
    ts = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y%m%dT%H%M%S%fZ")
    p = history.dir / f"{ts}_{kind}.json"
    p.write_text(json.dumps({"id": p.stem, "kind": kind, "root": "/x"}), encoding="utf-8")
    return p


def test_history_expire_by_age(tmp_path):
    cfg = _cfg(tmp_path)
    h = History(cfg)
    old, recent = _old_report(h, 100), _old_report(h, 5)
    (h.dir / "notes.json").write_text("{}")                # not one of ours: left alone
    assert h.expire(90) == 1
    assert not old.exists() and recent.exists() and (h.dir / "notes.json").exists()
    assert _events(cfg) == ["history.prune"]


def test_history_retention_is_applied_on_save(tmp_path):
    cfg = _cfg(tmp_path, history_retention_days=30)
    h = History(cfg)
    old = _old_report(h, 45)
    h.save(ScanReport(root="/x"), kind="scan")
    assert not old.exists() and len(list(h.dir.glob("*.json"))) == 1

    keep_all = History(_cfg(tmp_path / "other"))           # retention 0 = keep everything
    ancient = _old_report(keep_all, 4000)
    keep_all.save(ScanReport(root="/x"), kind="scan")
    assert ancient.exists()


def test_history_prune_cli_older_than(home):
    h = History()
    old = _old_report(h, 200)
    recent = _old_report(h, 1)
    assert runner.invoke(app, ["history", "prune", "--older-than", "junk"]).exit_code == 2
    res = runner.invoke(app, ["history", "prune", "--older-than", "90d"])
    assert res.exit_code == 0 and "Pruned 1" in res.output
    assert not old.exists() and recent.exists()
    assert runner.invoke(app, ["history", "prune", "--keep", "0"]).exit_code == 0     # original flag still works
    assert not recent.exists()


# -- license notices -----------------------------------------------------
def test_notices_cover_every_shipped_dependency():
    packages = {notices._norm(p["name"]): p for p in notices.collect()}
    for required in ("warden-scanner", "yara-x", "typer", "rich", "pefile", "psutil", "httpx", "cryptography"):
        assert required in packages, required
    # Development tools are not shipped and must not be listed as if they were.
    assert not {"pytest", "ruff", "mypy", "bandit", "hypothesis"} & set(packages)
    # Every listed component carries an actual license text.
    for name, p in packages.items():
        assert p["texts"], f"no license text for {name}"
    assert "YARA-X Authors" in packages["yara-x"]["texts"][0][1]


def test_notices_text_is_complete_and_marks_frozen_builds():
    text = notices.notices_text(frozen=False)
    assert "THIRD-PARTY SOFTWARE NOTICES" in text and "MIT License" in text
    assert "Python" in text and "OpenSSL" in text and "Apache" in text
    assert "PyInstaller bootloader" not in text
    assert "PyInstaller bootloader" in notices.notices_text(frozen=True)


def test_frozen_binary_prints_its_bundled_notices(tmp_path, monkeypatch):
    bundled = tmp_path / "THIRD_PARTY_NOTICES.txt"
    bundled.write_text("NOTICES BAKED IN AT BUILD TIME\n", encoding="utf-8")
    monkeypatch.setattr(notices, "BUNDLED", bundled)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert notices.notices_text() == "NOTICES BAKED IN AT BUILD TIME\n"


def test_licenses_cli(home):
    res = runner.invoke(app, ["licenses"])
    assert res.exit_code == 0 and "yara-x" in res.output and "MIT" in res.output
    full = runner.invoke(app, ["licenses", "--full"])
    assert full.exit_code == 0 and "Redistribution and use in source and binary forms" in full.output


def test_build_spec_bundles_the_notices():
    spec = (Path(__file__).resolve().parent.parent / "packaging" / "warden.spec").read_text(encoding="utf-8")
    assert "notices_text(frozen=True)" in spec and "THIRD_PARTY_NOTICES.txt" in spec


# -- posture -------------------------------------------------------------
def test_posture_json_structure_and_recommendations(home, monkeypatch):
    monkeypatch.setattr(scheduler, "_win_list_tasks", lambda: [])
    monkeypatch.setattr(scheduler, "_cron_current", lambda: ("", None))
    res = runner.invoke(app, ["posture", "--json"])
    assert res.exit_code == 0, res.output
    rep = json.loads(res.output)
    by = {c["id"]: c for c in rep["checks"]}
    assert set(by) >= {"engines", "signatures", "rules", "schedule", "last_scan", "quarantine",
                       "network", "audit", "retention", "data_dir", "secrets", "realtime"}
    assert all(c["status"] in ("ok", "attention", "info") for c in rep["checks"])
    assert by["engines"]["status"] == "ok" and by["network"]["status"] == "ok"
    assert by["schedule"]["status"] == "attention" and "schedule add" in by["schedule"]["advice"]
    assert by["last_scan"]["status"] == "attention"
    assert by["audit"]["status"] == "ok"
    assert by["realtime"]["status"] == "info" and "on-demand" in by["realtime"]["detail"]
    assert rep["attention"] == sum(1 for c in rep["checks"] if c["status"] == "attention")
    assert rep["warden_version"]


def test_posture_reflects_settings_and_strict_exit_code(home, tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler, "_win_list_tasks", lambda: [])
    monkeypatch.setattr(scheduler, "_cron_current", lambda: ("", None))
    assert runner.invoke(app, ["posture", "--strict"]).exit_code == 1       # fresh install: recommendations apply
    assert runner.invoke(app, ["posture"]).exit_code == 0                   # informational by default

    f = tmp_path / "n.txt"
    f.write_text("x")
    runner.invoke(app, ["scan", str(f), "--save"])
    runner.invoke(app, ["config", "set", "audit_log", "false"])
    runner.invoke(app, ["config", "set", "online_hash_lookup", "true"])
    by = {c["id"]: c for c in json.loads(runner.invoke(app, ["posture", "--json"]).output)["checks"]}
    assert by["last_scan"]["status"] == "ok"
    assert by["audit"]["status"] == "attention"
    assert by["network"]["status"] == "info" and "hashes are sent" in by["network"]["detail"]

    by = {c["id"]: c for c in json.loads(runner.invoke(app, ["--offline", "posture", "--json"]).output)["checks"]}
    assert by["network"]["status"] == "ok" and "offline" in by["network"]["detail"]


def test_posture_flags_a_tampered_audit_log(home, monkeypatch):
    monkeypatch.setattr(scheduler, "_win_list_tasks", lambda: [])
    monkeypatch.setattr(scheduler, "_cron_current", lambda: ("", None))
    runner.invoke(app, ["config", "set", "scan_archives", "false"])
    log = AuditLog()
    log.path.write_text(log.path.read_text(encoding="utf-8").replace("scan_archives", "x"), encoding="utf-8")
    by = {c["id"]: c for c in json.loads(runner.invoke(app, ["posture", "--json"]).output)["checks"]}
    assert by["audit"]["status"] == "attention" and "FAILED" in by["audit"]["detail"]


def test_privacy_report_lists_audit_log_and_retention(home):
    runner.invoke(app, ["config", "set", "history_retention_days", "90"])
    data = json.loads(runner.invoke(app, ["privacy", "--json"]).output)
    stored = data["stored_on_this_computer"]
    assert stored["audit_log"]["enabled"] is True and stored["audit_log"]["count"] == 1
    assert "OS user name" in stored["audit_log"]["contains"]
    assert stored["retention"]["history_retention_days"] == 90
    assert any("audit prune" in line for line in data["how_to_erase"])


# -- console output never crashes ---------------------------------------
def test_spinner_falls_back_to_ascii_outside_utf8():
    assert _spinner_name("utf-8") == "dots" and _spinner_name("UTF8") == "dots"
    for enc in ("cp1252", "cp437", "ascii", "latin-1"):
        assert _spinner_name(enc) == "line"


@pytest.mark.parametrize("encoding", ["ascii", "cp1252", "cp437"])
def test_scan_output_survives_a_non_unicode_stream(tmp_path, encoding):
    """Redirected output and legacy consoles are not UTF-8; a character that
    cannot be encoded must be replaced, never crash the scan."""
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "docs"
    target.mkdir()
    try:
        (target / "résumé — 日本語.pdf.exe").write_bytes(b"x")
    except OSError:
        pytest.skip("filesystem cannot store this file name")
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "PYTHONIOENCODING": encoding}
    env.pop("PYTHONUTF8", None)
    proc = subprocess.run([sys.executable, "-m", "warden", "scan", str(target)],
                          capture_output=True, env=env, timeout=120,
                          cwd=str(Path(__file__).resolve().parent.parent))
    assert proc.returncode == 1, proc.stderr.decode("ascii", "replace")[-800:]
    assert b"UnicodeEncodeError" not in proc.stderr and b"Traceback" not in proc.stderr
    assert b"THREATS FOUND" in proc.stdout


# -- history: a scan with gaps is not listed as clean -------------------
def test_history_entries_carry_completeness(tmp_path):
    cfg = _cfg(tmp_path)
    h = History(cfg)
    clean = ScanReport(root="/a")
    gaps = ScanReport(root="/b", unreadable=["/b/locked (Permission denied)"])
    assert h.save(clean).complete is True
    assert h.save(gaps).complete is False
    by_root = {e.root: e for e in h.list()}
    assert by_root["/a"].complete is True and by_root["/b"].complete is False
    assert by_root["/b"].to_dict()["complete"] is False
    # A report from before the field existed is treated as complete.
    (h.dir / "20200101T000000000000Z_scan.json").write_text('{"root": "/old", "threats": 0}', encoding="utf-8")
    assert {e.root: e.complete for e in h.list()}["/old"] is True


def test_history_list_cli_marks_incomplete_scans(home, tmp_path):
    History().save(ScanReport(root="/b", unreadable=["/b/x (Permission denied)"]))
    res = runner.invoke(app, ["history", "list"])
    assert res.exit_code == 0 and "incomplete" in res.output


def test_dashboard_never_labels_every_threat_critical():
    js = (Path(__file__).resolve().parent.parent / "warden" / "gui" / "static" / "app.js").read_text(encoding="utf-8")
    assert "badge(5)" not in js                       # no hard-coded "Critical"
    assert "outcomeBadge(e)" in js and '"Incomplete"' in js
