"""Property-based / fuzz tests (Hypothesis).

Warden's whole job is to read hostile input: files built to break parsers, and
its own state files after something has scribbled on them. These tests state the
contract every such code path must keep - *never crash, never hang, never
escape its bounds* - and let Hypothesis hunt for a counter-example.

Each test documents the one failure mode it allows (a specific exception type,
or none at all).
"""

from __future__ import annotations

import http.client
import io
import json
import shlex
import threading
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from _builders import make_elf64, make_macho64, make_ole, make_vba_project, make_zip
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from rich.console import Console

from warden import binfmt, persistence, rulepacks, scheduler, sweep
from warden import quarantine as qmod
from warden.archive import ArchiveLimits, ArchiveStats, iter_members
from warden.cli import _esc
from warden.config import MAX_SCAN_BYTES, MIN_SCAN_BYTES, Config
from warden.engines import clamav
from warden.engines.base import ScanContext
from warden.engines.documents import DocumentEngine, ole_streams, vba_decompress
from warden.gui import server as gui
from warden.history import History
from warden.models import FileResult, Finding
from warden.quarantine import Quarantine, QuarantineError
from warden.reputation import OnlineReputation, _parse_cymru_txt
from warden.rulepacks import RulePackError, RulePackManager
from warden.scanner import Scanner
from warden.scheduler import Scheduler, SchedulerError, ScheduleSpec

FAST = settings(max_examples=150, deadline=None,
                suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
SLOW = settings(max_examples=40, deadline=None,
                suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])

# Arbitrary JSON documents: what a state file might contain after corruption.
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=40),
    lambda inner: st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=12), inner, max_size=5),
    max_leaves=20,
)

# Bytes that start like a real container, then go wrong.
MAGICS = [b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe\x00\x00\x00\x02",
          b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b\x08", b"BZh9", b"\xfd7zXZ\x00",
          b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"%PDF-1.7\n", b"{\\rtf1", b"\x01\x00\xb0\x00Attribut", b""]
hostile_bytes = st.builds(lambda m, tail: m + tail, st.sampled_from(MAGICS), st.binary(max_size=600))

VALID_SAMPLES = [make_elf64(rwx=True), make_macho64(signed=True),
                 make_ole({"A": b"x" * 5000, "b": b"small"}),
                 make_vba_project('Attribute VB_Name = "M"\r\nSub AutoOpen()\r\nEnd Sub\r\n'),
                 make_zip({"a.txt": b"hello", "d/b.bin": b"\x00" * 300})]


@st.composite
def mutated(draw):
    """A structurally valid file with a handful of bytes flipped/cut - the
    classic way to reach deep parser states that pure noise never does."""
    data = bytearray(draw(st.sampled_from(VALID_SAMPLES)))
    for _ in range(draw(st.integers(1, 12))):
        pos = draw(st.integers(0, len(data) - 1))
        data[pos] = draw(st.integers(0, 255))
    cut = draw(st.integers(0, len(data)))
    return bytes(data[:cut]) if draw(st.booleans()) else bytes(data)


@pytest.fixture(scope="module")
def scanner(tmp_path_factory):
    return Scanner(Config(data_dir=tmp_path_factory.mktemp("fuzz-data")))


# -- file parsers --------------------------------------------------------
@FAST
@given(hostile_bytes | mutated())
def test_binary_metadata_never_raises(data):
    info = binfmt.binary_info(data)
    assert info is None or isinstance(info, dict)
    json.dumps(info)                                   # always serializable for reports


@FAST
@given(hostile_bytes | mutated())
def test_archive_walk_never_raises_and_respects_limits(data):
    limits = ArchiveLimits(max_members=20, max_member_bytes=64 * 1024, max_total_bytes=256 * 1024)
    stats = ArchiveStats()
    total = 0
    for name, blob in iter_members(data, "x.bin", limits, stats):
        assert isinstance(name, str) and isinstance(blob, bytes)
        assert len(blob) <= limits.max_member_bytes
        total += len(blob)
    assert total <= limits.max_total_bytes + limits.max_member_bytes
    assert stats.members_scanned == 0                  # only the scanner counts scanned members


@FAST
@given(hostile_bytes | mutated(), st.sampled_from(["a.doc", "a.docx", "a.pdf", "a.rtf", "a.bin", "a.xlsm"]))
def test_document_engine_never_raises(data, name):
    for finding in DocumentEngine().scan(ScanContext.from_bytes(name, data)):
        assert isinstance(finding, Finding)
        json.dumps(finding.to_dict())


@FAST
@given(st.binary(max_size=2000), st.integers(0, 50))
def test_vba_decompress_is_total_and_bounded(data, offset):
    out = vba_decompress(data, offset, max_out=4096)
    assert isinstance(out, bytes) and len(out) <= 4096


@FAST
@given(hostile_bytes | mutated())
def test_ole_reader_never_raises(data):
    for name, blob in ole_streams(data):
        assert isinstance(name, str) and isinstance(blob, bytes)


@SLOW
@given(hostile_bytes | mutated(), st.sampled_from(["f.exe", "f.zip", "f.docm", "f.txt", "f", "f.pdf.exe"]))
def test_whole_scanner_never_raises_on_hostile_content(scanner, data, name):
    result = scanner.scan_bytes(name, data)
    assert isinstance(result, FileResult)
    json.dumps(result.to_dict())
    assert result.status in ("clean", "threat", "unknown")


# -- command-line / persistence parsers ---------------------------------
@FAST
@given(st.text(max_size=300))
def test_command_line_splitting_never_raises(command):
    assert all(isinstance(t, str) for t in sweep._split_command(command))
    for p in sweep._extract_exe_paths(command):
        assert isinstance(p, Path)


@FAST
@given(st.text(max_size=600), st.booleans())
def test_persistence_text_parsers_never_raise(text, system):
    for parse in (persistence.parse_systemd_unit, persistence.parse_desktop_entry,
                  lambda t: persistence.parse_crontab(t, system=system), persistence._anacron_commands):
        assert all(isinstance(c, str) and c for c in parse(text))
    item = persistence.PersistenceItem(kind="cron", source="<x>", command=text[:200], label="l")
    for f in persistence.assess(item, text):
        assert f.engine == "persistence"


@FAST
@given(st.binary(max_size=400))
def test_launchd_plist_parser_only_raises_valueerror(data):
    try:
        label, command, extra = persistence.parse_launchd_plist(data)
    except ValueError:
        return
    assert isinstance(label, str) and isinstance(command, str) and isinstance(extra, dict)


@FAST
@given(st.text(max_size=200), st.binary(max_size=600))
def test_small_text_parsers_never_raise(text, raw):
    _parse_cymru_txt(text)
    clamav.parse_version_output(text)
    clamav.parse_cvd_header(raw)
    clamav.parse_cvd_header(b"ClamAV-VDB:" + raw)
    try:
        qmod.parse_age(text)
    except ValueError:
        pass


# -- scheduler input -----------------------------------------------------
@FAST
@given(st.text(max_size=80))
def test_schedule_names_that_validate_are_inert(name):
    try:
        scheduler._validate_name(name)
    except SchedulerError:
        return
    # Anything accepted must be safe as a task-path component and a cron comment.
    assert name and all(c.isascii() and (c.isalnum() or c in "-_") for c in name)
    assert "\\" not in name and "/" not in name and "\n" not in name and ".." not in name


target_paths = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\n\r\x00\""),
    min_size=1, max_size=60)


@FAST
@given(target_paths, st.sampled_from(["hourly", "daily", "weekly"]),
       st.integers(0, 23), st.integers(0, 59))
def test_cron_line_keeps_target_as_one_argument(target, frequency, hh, mm):
    """Whatever the target path contains ($(), ;, backticks, spaces, quotes),
    the shell must see it as exactly one argument: no injection, no splitting."""
    scheduler._validate_target(target)
    spec = ScheduleSpec(name="job", kind="scan", target=target, frequency=frequency,
                        time=f"{hh:02d}:{mm:02d}")
    line = scheduler._cron_line(spec.to_dict())
    assert "\n" not in line and line.endswith("# warden:job")
    command = line.split(None, 5)[5]
    argv = shlex.split(command, comments=True)
    expected = spec.command_args()
    assert argv == expected
    assert argv[-1] == expected[-1] and argv[-2] == "--"


@FAST
@given(st.text(max_size=20))
def test_time_validation_only_accepts_real_times(value):
    try:
        scheduler._validate_time(value)
    except SchedulerError:
        return
    hh, mm = value.split(":")
    assert 0 <= int(hh) <= 23 and 0 <= int(mm) <= 59


@SLOW
@given(json_values)
def test_scheduler_survives_any_registry_content(tmp_path, doc):
    s = Scheduler(Config(data_dir=tmp_path))
    s.registry.write_text(json.dumps(doc), encoding="utf-8")
    for spec in s.list():
        assert isinstance(spec, ScheduleSpec)
    for call in (lambda: s.add(ScheduleSpec(name="bad name!", kind="sweep")),
                 lambda: s.diagnose()):
        try:
            call()
        except SchedulerError:
            pass


# -- config / state files ------------------------------------------------
@SLOW
@given(json_values)
def test_config_load_never_raises_and_stays_in_bounds(tmp_path, doc):
    (tmp_path / "config.json").write_text(json.dumps(doc), encoding="utf-8")
    cfg = Config.load(tmp_path)
    assert MIN_SCAN_BYTES <= cfg.max_scan_bytes <= MAX_SCAN_BYTES
    assert 0 <= cfg.quarantine_retention_days <= 36500
    for flag in (cfg.follow_symlinks, cfg.use_clamav, cfg.online_hash_lookup, cfg.offline,
                 cfg.scan_archives, cfg.check_signatures, cfg.quarantine_encryption):
        assert isinstance(flag, bool)
    assert all(isinstance(e, str) for e in cfg.skip_extensions)
    cfg.save()                                        # and it can always be written back
    assert Config.load(tmp_path).max_scan_bytes == cfg.max_scan_bytes


@SLOW
@given(st.dictionaries(
    st.sampled_from(["max_scan_bytes", "follow_symlinks", "use_clamav", "online_hash_lookup", "offline",
                     "scan_archives", "check_signatures", "quarantine_encryption",
                     "quarantine_retention_days", "skip_extensions", "virustotal_api_key"]),
    json_values, max_size=8))
def test_config_known_keys_with_wrong_types(tmp_path, doc):
    (tmp_path / "config.json").write_text(json.dumps(doc), encoding="utf-8")
    cfg = Config.load(tmp_path)
    assert MIN_SCAN_BYTES <= cfg.max_scan_bytes <= MAX_SCAN_BYTES
    assert isinstance(cfg.offline, bool) and isinstance(cfg.skip_extensions, set)


@SLOW
@given(json_values)
def test_quarantine_survives_any_index_content(tmp_path, doc):
    q = Quarantine(Config(data_dir=tmp_path))
    q.index_path.write_text(json.dumps(doc), encoding="utf-8")
    for entry in q.list_entries():
        assert isinstance(entry.id, str) or entry.id is not None
    for call in (lambda: q.restore("0123456789abcdef", tmp_path / "out.bin"),
                 lambda: q.delete("0123456789abcdef"),
                 lambda: q.rescan("0123456789abcdef"),
                 lambda: q.read_bytes("../../escape"),
                 lambda: q.export("0123456789abcdef", tmp_path / "x.wq")):
        try:
            call()
        except QuarantineError:
            pass
    assert q.purge(everything=True, dry_run=True) is not None
    assert not (tmp_path / "out.bin").exists()


@SLOW
@given(st.lists(json_values, max_size=4))
def test_history_survives_any_report_files(tmp_path, docs):
    h = History(Config(data_dir=tmp_path))
    for i, doc in enumerate(docs):
        (h.dir / f"2026010{i}T000000000000Z_scan.json").write_text(json.dumps(doc), encoding="utf-8")
    (h.dir / "20260109T000000000000Z_scan.json").write_text("{ not json", encoding="utf-8")
    for e in h.list():
        assert all(isinstance(getattr(e, f), str) for f in ("id", "kind", "when", "root", "path"))
        assert isinstance(e.files_scanned, int) and isinstance(e.threats, int)
        json.dumps(e.to_dict())
    h.load("20260100T000000000000Z_scan")
    h.prune(keep=1)


@SLOW
@given(json_values)
def test_reputation_cache_survives_any_content(tmp_path, doc):
    cfg = Config(data_dir=tmp_path)
    cfg.ensure_dirs()
    (cfg.cache_dir / "reputation.json").write_text(json.dumps(doc), encoding="utf-8")
    cfg.offline = True                                # never touch the network in tests
    rep = OnlineReputation(cfg)
    assert rep.check("a" * 64, "b" * 40) is None


@SLOW
@given(json_values, json_values)
def test_rulepack_state_and_keys_survive_any_content(tmp_path, state, key):
    mgr = RulePackManager(Config(data_dir=tmp_path))
    mgr.root.mkdir(parents=True, exist_ok=True)
    mgr.keys_dir.mkdir(parents=True, exist_ok=True)
    mgr.state_path.write_text(json.dumps(state), encoding="utf-8")
    (mgr.keys_dir / "0123456789abcdef.json").write_text(json.dumps(key), encoding="utf-8")
    assert isinstance(mgr.packs(), list)
    dirs, warnings = mgr.active_dirs()
    assert isinstance(dirs, list) and isinstance(warnings, list)
    assert isinstance(mgr.trusted_keys(), list)
    for call in (lambda: mgr.rollback("corp"), lambda: mgr.remove("corp")):
        try:
            call()
        except RulePackError:
            pass


# -- rule packs ----------------------------------------------------------
@FAST
@given(hostile_bytes)
def test_read_pack_only_raises_rulepackerror(data):
    with pytest.raises(RulePackError):
        rulepacks.read_pack(data)                     # random bytes are never a valid pack


@FAST
@given(st.text(max_size=60))
def test_accepted_pack_member_names_stay_inside_the_pack(tmp_path, name):
    try:
        rulepacks._validate_member_name(name)
    except RulePackError:
        return
    base = (tmp_path / "pack").resolve()
    assert (base / name).resolve().is_relative_to(base)
    assert not Path(name).is_absolute() and ".." not in name.split("/")


@SLOW
@given(st.dictionaries(st.text(max_size=30), st.binary(max_size=50), max_size=4), json_values)
def test_packs_with_arbitrary_members_and_manifest(members, manifest):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        for name, blob in members.items():
            assume(name and name != "manifest.json" and "\x00" not in name)
            zf.writestr(name, blob)
    try:
        m, files = rulepacks.read_pack(buf.getvalue())
    except RulePackError:
        return
    assert set(m["files"]) == set(files)              # anything accepted is self-consistent


# -- quarantine crypto ---------------------------------------------------
@SLOW
@given(st.binary(max_size=3000), st.integers(1, 700))
def test_sealed_stream_roundtrip_any_size(monkeypatch, data, chunk):
    monkeypatch.setattr(qmod, "_CHUNK", chunk)
    key = b"k" * 32
    out = io.BytesIO()
    qmod._seal_stream(iter([data]), out, key, b"aad")
    sealed = out.getvalue()
    assert b"".join(qmod._open_stream(io.BytesIO(sealed), key, b"aad", "x")) == data
    if data:
        assert data not in sealed or len(data) < 4


@SLOW
@given(st.binary(min_size=1, max_size=600), st.data())
def test_any_single_byte_change_to_sealed_data_is_detected(monkeypatch, data, draw):
    monkeypatch.setattr(qmod, "_CHUNK", 64)
    key = b"k" * 32
    out = io.BytesIO()
    qmod._seal_stream(iter([data]), out, key, b"aad")
    sealed = bytearray(out.getvalue())
    pos = draw.draw(st.integers(0, len(sealed) - 1))
    sealed[pos] ^= draw.draw(st.integers(1, 255))
    with pytest.raises(QuarantineError):
        b"".join(qmod._open_stream(io.BytesIO(bytes(sealed)), key, b"aad", "x"))


@FAST
@given(st.binary(max_size=400))
def test_opening_garbage_as_sealed_data_only_raises_quarantineerror(data):
    with pytest.raises(QuarantineError):
        b"".join(qmod._open_stream(io.BytesIO(data), b"k" * 32, b"aad", "x"))


# -- output safety -------------------------------------------------------
@FAST
@given(st.text(max_size=200))
def test_escaped_text_always_renders(text):
    console = Console(file=io.StringIO(), force_terminal=False, width=200)
    console.print(f"[red]{_esc(text)}[/]")            # MarkupError would fail the test
    rendered = console.file.getvalue()
    assert "\x1b" not in rendered and "\x07" not in rendered


@FAST
@given(json_values)
def test_report_models_from_untrusted_dicts(doc):
    if not isinstance(doc, dict):
        doc = {"findings": doc, "path": doc, "meta": doc}
    try:
        result = FileResult.from_dict(doc)
    except (ValueError, TypeError, AttributeError, KeyError):
        return                                         # rejected cleanly; callers treat it as invalid
    assert isinstance(result.meta, dict)


# -- dashboard API -------------------------------------------------------
@pytest.fixture(scope="module")
def fuzz_server(tmp_path_factory):
    home = tmp_path_factory.mktemp("fuzz-home")
    mp = pytest.MonkeyPatch()
    mp.setenv("HOME", str(home))
    mp.setenv("USERPROFILE", str(home))
    mp.setattr(gui, "JOBS", gui.JobManager())
    mp.setattr(gui, "_run_scan_job", lambda job_id, *a, **k: gui.JOBS.update(job_id, status="error", error="x"))
    mp.setattr(gui, "_run_sweep_job", lambda job_id, *a, **k: gui.JOBS.update(job_id, status="error", error="x"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), gui.Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()
    mp.undo()


POST_ENDPOINTS = ["/api/scan", "/api/sweep", "/api/quarantine/add", "/api/quarantine/restore",
                  "/api/quarantine/delete", "/api/job/0123456789ab/cancel", "/api/unknown"]


def _post(port, path, payload: bytes):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", path, body=payload, headers={
        "Host": f"127.0.0.1:{port}", "X-Warden-Token": gui._TOKEN, "Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


@settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.sampled_from(POST_ENDPOINTS), json_values)
def test_dashboard_never_500s_on_arbitrary_json(fuzz_server, endpoint, doc):
    status, body = _post(fuzz_server, endpoint, json.dumps(doc).encode())
    assert status < 500, (endpoint, doc, body)
    assert isinstance(json.loads(body), dict)


@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.sampled_from(POST_ENDPOINTS), st.binary(max_size=300))
def test_dashboard_never_500s_on_arbitrary_bytes(fuzz_server, endpoint, payload):
    status, body = _post(fuzz_server, endpoint, payload)
    assert status < 500, (endpoint, payload, body)


@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters="?#"),
               max_size=60))
def test_dashboard_get_paths_never_500(fuzz_server, tail):
    for prefix in ("/api/history/", "/api/job/", "/static/", "/"):
        conn = http.client.HTTPConnection("127.0.0.1", fuzz_server, timeout=10)
        conn.request("GET", prefix + tail, headers={"Host": f"127.0.0.1:{fuzz_server}",
                                                    "X-Warden-Token": gui._TOKEN})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status < 500, prefix + tail


# -- audit log -----------------------------------------------------------
@SLOW
@given(st.lists(st.binary(max_size=120) | json_values.map(lambda v: json.dumps(v).encode()), max_size=6),
       st.dictionaries(st.text(max_size=10), json_values, max_size=4))
def test_audit_log_survives_any_file_content(tmp_path, lines, details):
    from warden.audit import AuditLog
    log = AuditLog(Config(data_dir=tmp_path))
    log.dir.mkdir(parents=True, exist_ok=True)
    log.path.write_bytes(b"\n".join(lines) + (b"\n" if lines else b""))
    res = log.verify()                                  # never raises on junk
    assert isinstance(res["ok"], bool) and isinstance(res["problems"], list)
    assert isinstance(log.entries(), list)
    entry = log.record("fuzz.event", **{f"k{i}": v for i, v in enumerate(details.values())})
    assert entry is not None and entry["event"] == "fuzz.event"   # a damaged log never blocks new entries
    json.dumps(entry)
    assert log.entries()[-1]["hash"] == entry["hash"]
    log.prune(0)
