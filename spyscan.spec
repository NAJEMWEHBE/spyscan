# spyscan.spec -- PyInstaller build spec for the SpyScan standalone Windows app.
#
# Build:
#     .\.venv\Scripts\pyinstaller spyscan.spec --noconfirm        # one-folder (default)
#     $env:SPYSCAN_ONEFILE=1; .\.venv\Scripts\pyinstaller spyscan.spec --noconfirm  # one-file
#
# Produces dist\SpyScan\SpyScan.exe (one-folder) or dist\SpyScan.exe (one-file).
# Windowed (no console). Bundles the UI, IOC indicator lists, and the shipped
# allowlist.
#
# The Sysinternals autorunsc binary is deliberately NOT bundled: its license forbids
# redistribution ("you may not publish the software for others to copy" / "transfer the
# software ... to any third party"), with no free/non-commercial exception. Autostart
# coverage ships via the native `autostart_native` collector instead; autorunsc is used
# only if the END USER installs their own copy (see src/spyscan/collectors/autoruns.py).
import os

ONEFILE = bool(os.environ.get("SPYSCAN_ONEFILE"))

block_cipher = None

# --- bundled read-only data (src -> bundle path) -------------------------------
# UI assets and indicator lists go UNDER the package (spyscan/...) so the package-
# relative resource_dir() finds them; config + tools go at the bundle root so
# bundle_dir() finds them. These mirrors must match src/spyscan/resources.py.
datas = [
    ("src/spyscan/app/ui/index.html", "spyscan/app/ui"),
    ("src/spyscan/app/ui/app.css", "spyscan/app/ui"),
    ("src/spyscan/app/ui/app.js", "spyscan/app/ui"),
    ("src/spyscan/rules/indicators/mercenary_domains.txt", "spyscan/rules/indicators"),
    ("src/spyscan/rules/indicators/mercenary_procnames.txt", "spyscan/rules/indicators"),
    ("config/allowlist.json", "config"),
    # ("tools/autorunsc64.exe", "tools"),  # REMOVED: Sysinternals license forbids
    # redistribution. Autostart coverage now ships via the native autostart_native
    # collector; a user may still install their own autorunsc (see collectors/autoruns.py).
]

# --- hidden imports ------------------------------------------------------------
# pywebview lazily imports its platform backend by name, and the .NET WinForms
# backend pulls clr/pythonnet at runtime -- PyInstaller's static analysis misses
# these, so name them explicitly. Flask/Werkzeug are imported normally but listed
# defensively. psutil/pefile back the collectors.
hiddenimports = [
    # pywebview Windows backends
    "webview",
    "webview.platforms.winforms",
    "webview.platforms.edgechromium",
    "webview.platforms.mshtml",
    "webview.platforms.win32",
    # .NET bridge used by the winforms backend
    "clr_loader",
    "clr_loader.netfx",
    "pythonnet",
    "clr",
    # web stack
    "flask",
    "werkzeug",
    "jinja2",
    # collector backends
    "psutil",
    "pefile",
]

a = Analysis(
    ["app_main.py"],
    pathex=["src"],            # so `import spyscan` resolves the src/ layout
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest", "pydoc"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

if ONEFILE:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        [],
        name="SpyScan",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        runtime_tmpdir=None,
        console=False,            # windowed: no console pops up
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="SpyScan",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,            # windowed: no console pops up
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="SpyScan",
    )
