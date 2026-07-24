# app_main.py -- PyInstaller entry point for the SpyScan standalone app.
"""Frozen-build entry. Kept tiny and at the repo root because PyInstaller freezes
a script cleaner than a ``-m package`` invocation. All real logic lives in
``spyscan.app.launch:main`` (the same entry the ``spyscan app`` CLI uses)."""
from spyscan.app.launch import main

if __name__ == "__main__":
    raise SystemExit(main())
