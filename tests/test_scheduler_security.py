"""Security tests for the scheduler (crontab / schtasks command construction)."""

import shlex

import pytest

from warden.config import Config
from warden.scheduler import Scheduler, ScheduleSpec, SchedulerError, _cron_line


def test_cron_line_quotes_target_against_injection():
    """A target with shell metacharacters must be a single quoted token."""
    evil = "/tmp/a; touch /tmp/pwned"
    line = _cron_line(ScheduleSpec(name="job", kind="scan", target=evil).to_dict())
    command = line.split("  # warden:")[0]
    # Drop the 5 cron schedule fields; the rest is the command line.
    command = command.split(None, 5)[5]
    tokens = shlex.split(command)
    assert evil in tokens                     # preserved as ONE argument
    assert "touch" not in tokens              # not parsed as a separate command


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
