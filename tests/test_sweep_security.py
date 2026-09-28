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
    monkeypatch.setattr(sweep.os.path, "isfile", lambda p: True)  # pretend System32 pwsh exists
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
    # And PowerShell must be invoked by ABSOLUTE path (no CWD/PATH hijack).
    assert captured["cmd"][0].lower().endswith("powershell.exe")
    assert "\\" in captured["cmd"][0] or "/" in captured["cmd"][0]


def test_powershell_resolves_to_system_absolute(monkeypatch):
    import os
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(sweep.os.path, "isfile", lambda p: True)
    # Build the expected path the same way the code does, so the assertion is
    # separator-agnostic (os.path.join uses '/' on POSIX CI runners).
    expected = os.path.join(r"C:\Windows", "System32", "WindowsPowerShell",
                            "v1.0", "powershell.exe")
    assert sweep._powershell_exe() == expected


def test_extract_exe_paths_includes_interpreter_payload(tmp_path):
    """Script/DLL args of an interpreter must be extracted, not just the interpreter."""
    wscript = tmp_path / "wscript.exe"
    wscript.write_bytes(b"MZ")
    evil = tmp_path / "evil.vbs"
    evil.write_bytes(b"x")
    paths = sweep._extract_exe_paths(f'"{wscript}" "{evil}"')
    assert wscript in paths and evil in paths


def test_extract_exe_paths_rundll32_comma(tmp_path):
    r = tmp_path / "rundll32.exe"
    r.write_bytes(b"MZ")
    dll = tmp_path / "evil.dll"
    dll.write_bytes(b"MZ")
    paths = sweep._extract_exe_paths(f'"{r}" "{dll}",Run')
    assert dll in paths


def test_is_signed_returns_none_off_windows(monkeypatch):
    monkeypatch.setattr(sweep, "IS_WINDOWS", False)
    assert sweep._is_signed(Path("/tmp/whatever")) is None
