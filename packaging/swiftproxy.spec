# -*- mode: python ; coding: utf-8 -*-
# SwiftProxy — unified PyInstaller spec for Windows / macOS / Linux.

import os
import platform

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None
_platform = platform.system().lower()

certifi_datas = collect_data_files('certifi')
webview_datas = collect_data_files('webview')

_i18n_path = os.path.join(os.path.dirname(SPEC), os.pardir, 'ui', 'i18n')
_web_path = os.path.join(os.path.dirname(SPEC), os.pardir, 'ui', 'web')
_lists_base = os.path.join(os.path.dirname(SPEC), os.pardir, 'resources', 'lists')

_entry = os.path.join(os.path.dirname(SPEC), os.pardir, 'main.py')

a = Analysis(
    [_entry],
    pathex=[],
    binaries=[],
    datas=[
        (_i18n_path, 'ui/i18n'),
        (_web_path, 'ui/web'),
    ] + certifi_datas + webview_datas,
    hiddenimports=[
        'pystray._win32' if _platform == 'windows' else 'pystray._xorg',
        'PIL._tkinter_finder',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.algorithms',
        'cryptography.hazmat.primitives.ciphers.modes',
        'cryptography.hazmat.backends.openssl',
        'webview.platforms.winforms' if _platform == 'windows'
        else ('webview.platforms.cocoa' if _platform == 'darwin'
              else 'webview.platforms.gtk'),
        'proxy', 'config', 'telegram', 'dns', 'hosts', 'lists', 'ui', 'tray',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PySide6', 'PyQt6', 'customtkinter', 'qfluentwidgets',
        'tgcrypto', 'nuitka',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SwiftProxy',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=os.path.join(os.path.dirname(SPEC), os.pardir, 'icon.ico'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SwiftProxy',
)