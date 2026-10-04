"""Security tests for the scheduler (crontab / schtasks command construction)."""

import shlex

import pytest

from warden.config import Config
from warden.scheduler import Scheduler, SchedulerError, ScheduleSpec, _cron_line


def test_cron_line_quotes_target_against_injection():
    """A target with shell metacharacters must be a single quoted token."""
    import os
    evil = "/tmp/a; touch /tmp/pwned"
    line = _cron_line(ScheduleSpec(name="job", kind="scan", target=evil).to_dict())
    command = line.split("  # warden:")[0]
    # Drop the 5 cron schedule fields; the rest is the command line.
    command = command.split(None, 5)[5]
    tokens = shlex.split(command)
    # The target is absolutized and passed after `--`; it must remain ONE token.
    assert os.path.abspath(evil) in tokens
    assert "touch" not in tokens              # not parsed as a separate command
    assert "--" in tokens                     # positional separator present


@pytest.mark.parametrize("bad", ["../evil", "a b", "a;b", "a\nb", "", "x" * 65, "a/b", "a\\b"])
def test_add_rejects_malicious_names(tmp_path, bad):
    sched = Scheduler(Config(data_dir=tmp_path))
    with pytest.raises(SchedulerError):
        sched.add(ScheduleSpec(name=bad, kind="sweep"))
    # Nothing should have been persisted.
    assert sched.list() == []


@pytest.mark.parametrize("bad_target", ['a"b', "a\nb", "a\x00b"])
def test_add_rejects_malicious_targets(tmp_path, bad_target):
    sched = Scheduler(Config(data_dir=tmp_path))
    with pytest.raises(SchedulerError):
        sched.add(ScheduleSpec(name="job", kind="scan", target=bad_target))


def test_add_rejects_bad_min_severity(tmp_path):
    sched = Scheduler(Config(data_dir=tmp_path))
    with pytest.raises(SchedulerError):
        sched.add(ScheduleSpec(name="job", kind="sweep", min_severity="; rm -rf ~"))


def test_command_args_uses_separator_and_absolute_target():
    import os
    args = ScheduleSpec(name="j", kind="scan", target="rel/sub/path").command_args()
    assert "--" in args
    target = args[args.index("--") + 1]
    assert os.path.isabs(target)


def test_remove_unknown_still_attempts_os_cleanup(tmp_path, monkeypatch):
    sched = Scheduler(Config(data_dir=tmp_path))
    cleaned = []
    monkeypatch.setattr(sched, "_remove_os_task", lambda name: cleaned.append(name))
    with pytest.raises(SchedulerError):
        sched.remove("orphan")
    assert cleaned == ["orphan"]     # OS-level cleanup attempted despite absence
