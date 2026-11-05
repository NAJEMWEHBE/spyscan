"""Audit #14: the opt-in Defender check must not destroy evidence or misread hits.

- MpCmdRun applies Defender's default action (quarantine) on a hit unless
  -DisableRemediation is passed: that deletes the evidence and can tip off an
  abuser who watches the machine.
- "found 10 threats" contains the clean marker "0 threats" and parsed as clean.
- MpCmdRun's exit code 2 means "threats found" even when no name is printed.
"""
from __future__ import annotations
import subprocess
import types

from spyscan.enrich import defender


def test_scan_never_lets_defender_remediate(monkeypatch):
    seen = {}

    def fake_run(args, **kw):
        seen["args"] = args
        return types.SimpleNamespace(stdout="found no threats.", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    defender.scan_file(r"C:\x\a.exe")
    assert "-DisableRemediation" in seen["args"]
    assert seen["args"][seen["args"].index("-File") + 1] == r"C:\x\a.exe"


def test_ten_threats_is_not_clean():
    out = ("Scanning C:\\x\\a.exe found 10 threats.\n"
           "Threat                  : Trojan:Win32/Meterpreter\n")
    assert defender.parse_status(out)["defender_hit"] is True


def test_zero_threats_is_clean():
    assert defender.parse_status("Scanning C:\\x\\a.exe found 0 threats.")["defender_hit"] is False


def test_exit_code_two_is_a_hit_even_without_a_threat_name(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: types.SimpleNamespace(
        stdout="Scanning C:\\x\\a.exe found 1 threats.", stderr="", returncode=2))
    r = defender.scan_file(r"C:\x\a.exe")
    assert r["defender_hit"] is True


def test_exit_code_zero_with_clean_text_is_no_hit(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: types.SimpleNamespace(
        stdout="Scan finished.\nScanning C:\\x\\a.exe found no threats.", stderr="",
        returncode=0))
    assert defender.scan_file(r"C:\x\a.exe")["defender_hit"] is False
