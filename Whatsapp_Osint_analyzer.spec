# -*- mode: python ; coding: utf-8 -*-


# Явные импорты прерывают сборку, если зависимости не установлены.
import customtkinter
import tkinterdnd2
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

project_dir = Path(SPECPATH)
icon_path = str(project_dir / 'icon.ico')

ctk_data, ctk_binaries, ctk_imports = collect_all("customtkinter")
dnd_data, dnd_binaries, dnd_imports = collect_all("tkinterdnd2")

extra_data, extra_binaries, extra_imports = [], [], []
for package in ('pymupdf', 'faster_whisper', 'ctranslate2', 'av', 'tokenizers', 'huggingface_hub', 'onnxruntime', 'phonenumbers'):
    __import__(package)
    data, binaries, imports = collect_all(package)
    extra_data.extend(data)
    extra_binaries.extend(binaries)
    extra_imports.extend(imports)
extra_imports.extend(['PIL.Image', 'PIL.ImageTk'])

a = Analysis(
    [str(project_dir / 'main.py')],
    pathex=[str(project_dir)],
    binaries=ctk_binaries + dnd_binaries + extra_binaries,
    datas=ctk_data + dnd_data + extra_data + [(icon_path, '.')],
    hiddenimports=ctk_imports + dnd_imports + extra_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Whatsapp_Osint_analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)
