"""Security tests for the system sweep (Authenticode signature check)."""

import types
from pathlib import Path

from warden import sweep


def test_is_signed_never_interpolates_path_into_powershell(monkeypatch):
    """A crafted filename must not reach the PowerShell -Command string.

    Regression for a command-injection where `'{path}'` let a filename break out
    of the string literal and execute code.
    """
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["env"] = kw.get("env")
        return types.SimpleNamespace(stdout="NotSigned", returncode=0)

    monkeypatch.setattr(sweep, "IS_WINDOWS", True)
    monkeypatch.setattr(sweep.subprocess, "run", fake_run)
    sweep._SIGN_CACHE.clear()

    evil = r"a'; Start-Process calc; $(rm x) ; '.exe"
    sweep._is_signed(Path(evil))

    # The command must be a fixed script that references an env var, and the
    # attacker-controlled string must appear ONLY in the environment.
    command = " ".join(captured["cmd"])
    assert "$env:WARDEN_SIGPATH" in command
    assert evil not in command
    assert "Start-Process" not in command
    assert captured["env"]["WARDEN_SIGPATH"] == evil


def test_is_signed_returns_none_off_windows(monkeypatch):
    monkeypatch.setattr(sweep, "IS_WINDOWS", False)
    assert sweep._is_signed(Path("/tmp/whatever")) is None
