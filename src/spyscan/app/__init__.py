# src/spyscan/app/__init__.py
"""Standalone desktop app shell for spyscan.

A tiny localhost-only Flask API (server.py) wrapping the reusable scan service,
a dependency-free vanilla UI (ui/), and a native-window launcher (launch.py).
The engine is untouched -- this is purely a GUI shell over spyscan.service.
"""
