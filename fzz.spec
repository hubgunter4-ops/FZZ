# -*- mode: python ; coding: utf-8 -*-
"""Portable one-file build for Linux and Windows."""
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH)

analysis = Analysis(
    [str(ROOT / "packaging" / "fzz_entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / "resources" / "payloads.yml"), "resources"),
        (str(ROOT / "resources" / "safe-checks.yml"), "resources"),
    ],
    hiddenimports=collect_submodules("fzztool"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "setuptools"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
executable = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="fzz",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
