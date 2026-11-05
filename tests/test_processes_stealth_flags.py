"""Audit #11: the hidden-window signal must recognise real PowerShell syntax.

hidden_flag looked for an exact '-hidden' list element, which PowerShell does
not have; '-WindowStyle Hidden' and '-w hidden' (what implants actually use)
were missed. -EncodedCommand (-enc / -e / -ec) is flagged separately.
"""
from __future__ import annotations
import pytest

from spyscan.collectors.processes import parse
from spyscan.facts import Fact
from spyscan.score import score_fact


def _attrs(cmdline):
    return parse([{"pid": 1, "name": "powershell.exe", "exe": r"c:\p.exe", "ppid": 0,
                   "pname": "", "cmdline": cmdline}])[0].attrs


@pytest.mark.parametrize("cmdline", [
    ["powershell.exe", "-WindowStyle", "Hidden"],
    ["powershell.exe", "-w", "hidden", "-c", "x"],
    ["powershell.exe", "-win", "HIDDEN"],
    ["pwsh.exe", "-windowstyle:hidden"],
    ["powershell.exe", "-NoP", "-W", "Hidden", "-File", "a.ps1"],
    ["u.exe", "-hidden"],
])
def test_hidden_window_is_flagged(cmdline):
    assert _attrs(cmdline)["hidden_flag"] is True


@pytest.mark.parametrize("cmdline", [
    ["powershell.exe", "-WindowStyle", "Normal"],
    ["powershell.exe", "-File", "hidden.ps1"],
    ["notepad.exe", "C:\\notes\\hidden-things.txt"],
    [],
])
def test_no_false_hidden_flag(cmdline):
    assert _attrs(cmdline)["hidden_flag"] is False


@pytest.mark.parametrize("flag", ["-enc", "-e", "-ec", "-EncodedCommand", "-ENC"])
def test_encoded_command_is_flagged(flag):
    assert _attrs(["powershell.exe", flag, "SQBFAFgA"])["encoded_flag"] is True


def test_plain_process_carries_no_encoded_key():
    # absent (not False) so existing baselines do not see every process as changed
    assert "encoded_flag" not in _attrs(["powershell.exe", "-NoProfile", "-File", "a.ps1"])


def test_encoded_flag_scores():
    r = score_fact(Fact("processes", "processes::p::p", "process", "p", {"encoded_flag": True}))
    assert r["score"] == 1 and any("encoded" in x.lower() for x in r["reasons"])
