# tests/test_resources.py
"""Unit tests for the frozen-aware resource resolver.

We simulate a PyInstaller bundle by setting ``sys.frozen`` + ``sys._MEIPASS``
(and ``sys.executable``) via monkeypatch -- no real freeze needed.
"""
import sys
from pathlib import Path

from spyscan import resources


def test_dev_mode_resource_dir_is_package_relative():
    # Not frozen in the test runner -> resolves against the package (src/spyscan).
    assert resources.is_frozen() is False
    d = resources.resource_dir("app", "ui")
    assert d.name == "ui"
    # the dev path actually exists in the tree
    assert (d / "index.html").exists()
    # indicators too
    ind = resources.resource_dir("rules", "indicators")
    assert (ind / "mercenary_domains.txt").exists()


def test_dev_mode_bundle_dir_is_repo_root():
    # bundle-root resources (config/, tools/) resolve at the repo root in dev
    assert (resources.bundle_dir("config", "allowlist.json")).exists()


def test_dev_mode_app_base_is_repo_root():
    base = resources.app_base()
    assert (base / "pyproject.toml").exists()


def test_frozen_resource_dir_uses_meipass_package(monkeypatch, tmp_path):
    meipass = tmp_path / "_MEI12345"
    meipass.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    d = resources.resource_dir("rules", "indicators")
    assert d == meipass / "spyscan" / "rules" / "indicators"


def test_frozen_bundle_dir_uses_meipass_root(monkeypatch, tmp_path):
    meipass = tmp_path / "_MEI12345"
    meipass.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    assert resources.bundle_dir("tools", "autorunsc64.exe") == meipass / "tools" / "autorunsc64.exe"
    assert resources.bundle_dir("config") == meipass / "config"


def test_frozen_app_base_is_exe_dir(monkeypatch, tmp_path):
    exe = tmp_path / "dist" / "SpyScan" / "SpyScan.exe"
    exe.parent.mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "_MEI"), raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    assert resources.app_base() == exe.parent
