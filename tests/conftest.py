"""Shared fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """Point Warden's per-user data dir (~/.warden) at a throwaway directory,
    so CLI-level tests never read or write the developer's real state."""
    fake = tmp_path / "home"
    fake.mkdir()
    monkeypatch.setenv("HOME", str(fake))
    monkeypatch.setenv("USERPROFILE", str(fake))
    monkeypatch.delenv("WARDEN_VT_API_KEY", raising=False)
    monkeypatch.delenv("WARDEN_OFFLINE", raising=False)
    return fake
