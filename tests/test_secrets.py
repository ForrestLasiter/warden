"""Tests for the at-rest secret store (P0 #6)."""

import os


def test_secret_store_roundtrip(tmp_path, monkeypatch):
    from warden import secrets
    monkeypatch.setattr(secrets, "default_data_dir", lambda: tmp_path)
    # Force deterministic backend across CI: DPAPI on Windows, file elsewhere.
    monkeypatch.setattr(secrets, "_IS_MACOS", False)
    monkeypatch.setattr(secrets.shutil, "which", lambda name: None)

    secrets.store_secret("vt", "my-secret-key-123")
    assert secrets.load_secret("vt") == "my-secret-key-123"

    # On POSIX the fallback file must be owner-only; never world-readable.
    if os.name != "nt":
        f = tmp_path / "secrets" / "vt"
        assert f.exists() and (f.stat().st_mode & 0o077) == 0

    secrets.delete_secret("vt")
    assert secrets.load_secret("vt") is None


def test_load_missing_secret_returns_none(tmp_path, monkeypatch):
    from warden import secrets
    monkeypatch.setattr(secrets, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr(secrets, "_IS_MACOS", False)
    monkeypatch.setattr(secrets.shutil, "which", lambda name: None)
    assert secrets.load_secret("nope") is None


def test_file_fallback_not_world_readable_dir(tmp_path, monkeypatch):
    from warden import secrets
    monkeypatch.setattr(secrets, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr(secrets, "_IS_MACOS", False)
    monkeypatch.setattr(secrets.shutil, "which", lambda name: None)
    secrets.store_secret("x", "y")
    if os.name != "nt":
        assert ((tmp_path / "secrets").stat().st_mode & 0o077) == 0
