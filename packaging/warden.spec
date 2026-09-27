# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single-file `warden` executable.

Bundles the yara-x native extension plus Warden's own data files (the YARA
rules and the GUI's static assets), so the resulting binary is fully
self-contained and needs no Python install.

Build (from the repo root, with the project + pyinstaller installed):
    pyinstaller packaging/warden.spec --noconfirm
Output:
    dist/warden        (Linux/macOS)
    dist/warden.exe    (Windows)
"""

import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

# Repo root (this spec lives in packaging/). Putting it on the search path makes
# PyInstaller find the `warden` package as a plain directory, regardless of how
# it was installed (editable/PEP 660 installs are otherwise opaque to analysis).
REPO_ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))

# Windows uses the .ico for the exe icon; other platforms ignore it.
ICON = os.path.join(REPO_ROOT, "assets", "warden.ico") if sys.platform == "win32" else None

datas = []
binaries = []
hiddenimports = []

# Force-include every warden submodule so nothing is missed by static analysis.
hiddenimports += collect_submodules("warden")

# yara-x ships a compiled extension + metadata; grab everything it needs.
_yx_datas, _yx_bins, _yx_hidden = collect_all("yara_x")
datas += _yx_datas
binaries += _yx_bins
hiddenimports += _yx_hidden

# Warden's own package data: YARA rules and the dashboard's static files.
datas += collect_data_files(
    "warden",
    includes=["rules/*.yar", "rules/*.yara", "gui/static/*"],
)

# typer/rich/click are pure-python but pull a few lazy imports.
hiddenimports += ["warden", "warden.gui", "warden.gui.server"]

a = Analysis(
    ["entry.py"],
    pathex=[REPO_ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="warden",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON,
)
