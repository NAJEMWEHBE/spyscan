"""Ordinary Windows entries in a baseline scan: a Microsoft driver keeps the floor
whatever its folder is called, and a Microsoft-signed entry the floor refuses says
why among its reasons.

Each fact is new since the baseline, Microsoft-signed and verified, with no other
signal unless the case names one.
"""
from __future__ import annotations
import pytest

from spyscan.allowlist import REFUSED_OUTSIDE, Allowlist
from spyscan.collectors.base import is_tempish, split_command
from spyscan.facts import Fact
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher

MS = {"signed": True, "verified": True, "trusted_ms": True,
      "signer": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}
ANCHOR = Fact("processes", "processes::anchor", "process", "anchor", {"exe": r"c:\a.exe"})
FLOORED = ["allowlisted: Microsoft-signed"]
SAYS_WHY = REFUSED_OUTSIDE + ", so it is scored like any other program"

_ENV = {
    "SystemRoot": "C:\\Windows", "windir": "C:\\Windows", "SystemDrive": "C:",
    "ProgramFiles": "C:\\Program Files", "ProgramW6432": "C:\\Program Files",
    "ProgramFiles(x86)": "C:\\Program Files (x86)", "ProgramData": "C:\\ProgramData",
    "TEMP": "C:\\Users\\v\\AppData\\Local\\Temp", "TMP": "C:\\Users\\v\\AppData\\Local\\Temp",
    "APPDATA": "C:\\Users\\v\\AppData\\Roaming", "LOCALAPPDATA": "C:\\Users\\v\\AppData\\Local",
}


@pytest.fixture(autouse=True)
def _windows_env(monkeypatch):
    for key, value in _ENV.items():
        monkeypatch.setenv(key, value)


def _new_since_baseline(fact):
    """The finding for ``fact`` in a scan whose baseline lacks it, and the paths signed."""
    signed = []

    def signer(path):
        signed.append(path)
        return dict(MS)

    out = build_findings([ANCHOR], [ANCHOR, fact], IOCMatcher(), signer=signer,
                         allowlist=Allowlist(), log=lambda *a: None)
    return next(f for f in out if f.fact.entity_key == fact.entity_key), signed


def _driver(path):
    return Fact("drivers", "drivers::d", "driver", "driver: D",
                {"module": "d", "path": path, "from_temp": is_tempish(path)})


@pytest.mark.parametrize("path", [
    pytest.param("C:\\Program Files\\WindowsApps\\Microsoft.GamingServices_31.106.13001.0_x64"
                 "\\drivers\\xvdd.sys", id="blank-in-program-files"),
    pytest.param("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25090.3009-0"
                 "\\Drivers\\WdNisDrv.sys", id="defender-platform"),
    pytest.param("C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates"
                 "\\{0C1A6F2B-7B7E-4C5A-9D0E-3F2B1A6C7D8E}\\MpKslDrv.sys", id="defender-definitions"),
    pytest.param("C:\\Windows\\System32\\drivers\\tcpip.sys", id="system32-drivers"),
])
def test_new_microsoft_driver_keeps_the_floor_whatever_its_folder_is_called(path):
    fd, signed = _new_since_baseline(_driver(path))
    assert signed == [path]                      # the whole path is one file, not a command
    assert (fd.bucket, fd.score, fd.reasons) == ("INFO", 0, FLOORED)


def test_new_microsoft_driver_outside_the_system_folders_is_scored_and_says_why():
    fd, _signed = _new_since_baseline(_driver("C:\\ProgramData\\Some Vendor\\drv.sys"))
    assert fd.bucket == "REVIEW"
    assert fd.reasons == [SAYS_WHY, "+4 new persistence entry since baseline"]


def test_new_per_user_microsoft_task_is_scored_and_says_why():
    run = "C:\\Users\\v\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe"
    task = Fact("services_tasks", "services_tasks::task::od", "scheduled_task", "task: OneDrive",
                {"name": "\\OneDrive Standalone Update Task", "task_to_run": run,
                 "from_temp": False})
    fd, _signed = _new_since_baseline(task)
    assert fd.bucket == "REVIEW"
    assert fd.reasons == [SAYS_WHY, "+4 new persistence entry since baseline"]


def test_floored_entry_shows_no_refusal_line():
    task = Fact("services_tasks", "services_tasks::task::ok", "scheduled_task", "task: OK",
                {"name": "\\Microsoft\\Windows\\OK", "from_temp": False,
                 "task_to_run": "C:\\Windows\\System32\\usoclient.exe"})
    fd, _signed = _new_since_baseline(task)
    assert (fd.bucket, fd.reasons) == ("INFO", FLOORED)


def test_a_command_longer_than_windows_accepts_is_not_searched_for_a_program():
    # an extension-less first word and an .exe only at the far end: within the limit the
    # search would take the whole line as the program; past it the cut stops at the first word
    cmd = "C:\\dir " + "x " * 20000 + "y.exe"
    cut = split_command(cmd)
    assert len(cmd) > 32767
    assert (cut.program, cut.exact, cut.skipped) == ("C:\\dir", False, ())
