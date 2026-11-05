"""Audit #20: a non-editable `pip install .` must find its data and keep state
out of Python's own Lib folder.

Installed, resources._DEV_ROOT ("three levels up") resolves to ...\\Lib, so the
IOC lists and allowlist loaded silently empty and baseline.db / runs\\ were
written into the Python install. We simulate that layout by pointing _DEV_ROOT
at a folder that is not a source checkout.
"""
from __future__ import annotations
from pathlib import Path

import pytest

from spyscan import resources, service


@pytest.fixture
def installed(tmp_path, monkeypatch):
    lib = tmp_path / "Python314" / "Lib"           # what parents[2] is when installed
    lib.mkdir(parents=True)
    monkeypatch.setattr(resources, "_DEV_ROOT", lib)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    return tmp_path


def test_source_checkout_is_detected():
    assert resources.is_source_checkout() is True


def test_installed_copy_is_not_a_source_checkout(installed):
    assert resources.is_source_checkout() is False


def test_installed_state_lives_in_local_appdata(installed):
    assert resources.app_base() == installed / "LocalAppData" / "spyscan"


def test_installed_indicators_come_from_the_package(installed, monkeypatch):
    monkeypatch.setattr(service, "ROOT", resources.app_base())
    ind = service.indicators_dir()
    assert ind == resources.resource_dir("rules", "indicators")
    assert (ind / "mercenary_procnames.txt").is_file()


def test_source_checkout_keeps_the_root_relative_layout(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    assert service.indicators_dir() == tmp_path / "src" / "spyscan" / "rules" / "indicators"


def test_frozen_is_unchanged(installed, monkeypatch):
    import sys
    exe = installed / "dist" / "SpyScan" / "SpyScan.exe"
    exe.parent.mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(installed / "_MEI"), raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    assert resources.app_base() == exe.parent
