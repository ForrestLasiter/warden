"""Tests for scan coverage reporting, symlink handling, and cycle safety."""

import os

import pytest

from warden.cli import _scan_exit_code
from warden.config import Config
from warden.scanner import Scanner


def _try_symlink(link, target, **kw):
    try:
        os.symlink(target, link, **kw)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")


def test_explicit_symlink_file_rejected_when_not_following(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("hello")
    link = tmp_path / "link.txt"
    _try_symlink(link, real)
    cfg = Config(data_dir=tmp_path, follow_symlinks=False)
    rep = Scanner(cfg).scan_path(link)
    assert rep.unreadable                       # recorded as a coverage gap
    assert not rep.coverage_complete
    assert _scan_exit_code(rep) == 2


def test_symlinked_directory_skipped_when_not_following(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "f.txt").write_text("x")
    link = tmp_path / "dlink"
    _try_symlink(link, d, target_is_directory=True)
    cfg = Config(data_dir=tmp_path, follow_symlinks=False)
    rep = Scanner(cfg).scan_path(link)
    assert rep.unreadable and not rep.coverage_complete


def test_symlink_cycle_terminates(tmp_path):
    root = tmp_path / "root"
    sub = root / "sub"
    sub.mkdir(parents=True)
    (root / "file.txt").write_text("content")
    _try_symlink(sub / "loop", root, target_is_directory=True)
    cfg = Config(data_dir=tmp_path, follow_symlinks=True)
    rep = Scanner(cfg).scan_path(root)           # must not hang
    scanned = [r.path for r in rep.results if r.path.endswith("file.txt")]
    assert len(scanned) == 1                     # real file scanned exactly once


def test_unreadable_directory_recorded(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("x")
    bad = tmp_path / "locked"
    bad.mkdir()
    import warden.scanner as sc
    real_scandir = os.scandir

    def fake_scandir(p):
        if str(p) == str(bad):
            raise PermissionError("access denied")
        return real_scandir(p)

    monkeypatch.setattr(sc.os, "scandir", fake_scandir)
    rep = Scanner(Config(data_dir=tmp_path)).scan_path(tmp_path)
    assert any("locked" in u for u in rep.unreadable)
    assert not rep.coverage_complete
    assert _scan_exit_code(rep) == 2


def test_skip_reason_counters(tmp_path):
    iso = tmp_path / "disk.iso"
    iso.write_bytes(b"x" * 100)
    big = tmp_path / "big.bin"
    big.write_bytes(b"y" * 500)
    cfg = Config(data_dir=tmp_path, max_scan_bytes=50)   # make big.bin "oversized"
    rep = Scanner(cfg).scan_path(tmp_path)
    assert rep.skipped_ext >= 1          # the .iso
    assert rep.skipped_oversized >= 1    # big.bin exceeds max_scan_bytes


def test_coverage_dict_shape(tmp_path):
    (tmp_path / "a.txt").write_text("ok")
    rep = Scanner(Config(data_dir=tmp_path)).scan_path(tmp_path)
    cov = rep.to_dict()["coverage"]
    assert cov["complete"] is True
    assert "skipped_by_extension" in cov and "unreadable_paths" in cov
