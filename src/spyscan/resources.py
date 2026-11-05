# src/spyscan/resources.py
"""Frozen-aware resource resolution.

The app ships two kinds of paths:

* **bundled read-only resources** -- UI assets, IOC indicator lists, the shipped
  allowlist, the autorunsc binary. When running from source these live in the
  project tree; when frozen by PyInstaller they are unpacked into ``sys._MEIPASS``
  (a temp dir). ``resource_dir`` resolves these.

* **writable runtime data** -- ``baseline.db`` and the ``runs/`` reports. These
  must NOT live in ``_MEIPASS`` (a one-file build wipes it on exit and it is a
  throwaway temp dir). They live next to the executable when frozen, at the
  project root in a source checkout, and in ``%LOCALAPPDATA%\\spyscan`` for a
  regular ``pip install`` (never Python's own ``Lib``). ``app_base`` resolves these.

Keeping both behind one tiny module means every other module asks here instead of
hand-rolling ``parents[...]`` walks that silently break once frozen.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

# Project root in DEV = three levels up from this file
# (src/spyscan/resources.py -> src/spyscan -> src -> repo root).
_DEV_ROOT = Path(__file__).resolve().parents[2]

# The spyscan package dir. In dev this is ``src/spyscan``; when frozen it is
# ``<_MEIPASS>/spyscan`` (our datas put the package tree under the bundle root).
# Resolving bundled resources RELATIVE TO THE PACKAGE makes one path work in both
# modes -- the ``src/`` prefix in dev simply disappears in the bundle.
_PKG_DIR = Path(__file__).resolve().parent


def is_frozen() -> bool:
    """True when running inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def _meipass() -> Path | None:
    """The PyInstaller unpack dir, or None when not frozen."""
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) if base else None


def resource_dir(*parts: str) -> Path:
    """Directory of a BUNDLED READ-ONLY resource, resolved against the package.

    Pass the path relative to the ``spyscan`` package, e.g.
    ``resource_dir("app", "ui")`` -> ``src/spyscan/app/ui`` in dev,
    ``<_MEIPASS>/spyscan/app/ui`` when frozen. ``parts`` empty -> the package dir.
    """
    if is_frozen():
        mp = _meipass()
        base = (mp / "spyscan") if mp else _PKG_DIR
    else:
        base = _PKG_DIR
    return base.joinpath(*parts)


def bundle_dir(*parts: str) -> Path:
    """Directory of a BUNDLED resource that sits at the BUNDLE ROOT (not under
    the package) -- e.g. ``config/`` and ``tools/``.

    Frozen: ``<_MEIPASS>/<parts...>``. Dev: ``<repo-root>/<parts...>``.
    """
    if is_frozen():
        base = _meipass() or Path(sys.executable).resolve().parent
    else:
        base = _DEV_ROOT
    return base.joinpath(*parts)


def is_source_checkout() -> bool:
    """True when running from a source tree (``<root>/pyproject.toml`` + ``src/``).

    False for a regular (non-editable) ``pip install``: there ``_DEV_ROOT`` is
    Python's ``Lib`` folder, which must never receive state (audit #20).
    """
    return (_DEV_ROOT / "pyproject.toml").is_file() and (_DEV_ROOT / "src" / "spyscan").is_dir()


def app_base() -> Path:
    """Base dir for WRITABLE runtime data (baseline.db, runs/).

    Frozen: the directory containing the executable. Source checkout: the project
    root. Installed package: ``%LOCALAPPDATA%\\spyscan`` (``~/.spyscan`` without it).
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    if is_source_checkout():
        return _DEV_ROOT
    local = os.environ.get("LOCALAPPDATA")
    return Path(local) / "spyscan" if local else Path.home() / ".spyscan"
