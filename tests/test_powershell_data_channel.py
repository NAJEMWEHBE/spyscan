"""Audit #1: data handed to PowerShell must never reach its parser as code.

PowerShell treats the curly quotes U+2018/U+2019/U+201A/U+201B as single quotes,
so escaping only ASCII ' inside a '...' literal lets a Startup-folder shortcut
named  a<U+2019>;Write-Output INJECTED;<U+2019>b.lnk  break out of the string. The
fix is structural: paths travel as JSON data (stdin), the script text is constant.
These tests sit at the subprocess boundary (the external system), not inside.
"""
from __future__ import annotations
import json
import subprocess
import types

from spyscan.collectors import autostart_native as an

EVIL = ("C:\\Users\\v\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        "\\a\u2019;Write-Output INJECTED;\u2019b.lnk")


def _capture(monkeypatch, stdout=b""):
    calls = []

    def fake_run(args, **kw):
        calls.append({"args": args, **kw})
        return types.SimpleNamespace(stdout=stdout, stderr=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _script_text(call) -> str:
    return " ".join(str(a) for a in call["args"])


def _data_sent(call):
    raw = call.get("input")
    if isinstance(raw, bytes):
        raw = raw.decode("ascii")
    return json.loads(raw)


def test_lnk_paths_never_appear_in_the_powershell_script(monkeypatch):
    calls = _capture(monkeypatch)
    an._lnk_targets([EVIL, "C:\\x\\plain.lnk"])
    assert len(calls) == 1
    script = _script_text(calls[0])
    assert "INJECTED" not in script
    assert "\u2019" not in script
    assert "plain.lnk" not in script


def test_lnk_paths_travel_as_json_data(monkeypatch):
    calls = _capture(monkeypatch)
    an._lnk_targets([EVIL])
    assert _data_sent(calls[0]) == [EVIL]
    # ASCII-only on the wire, so the console code page can never mangle it
    assert isinstance(calls[0]["input"], bytes)
    calls[0]["input"].decode("ascii")


def test_lnk_targets_maps_the_csv_reply(monkeypatch):
    reply = ('"Path","Target","Args"\r\n'
             f'"{EVIL}","C:\\t\\a.exe","-x"\r\n').encode("utf-8")
    _capture(monkeypatch, stdout=reply)
    assert an._lnk_targets([EVIL]) == {EVIL: ("C:\\t\\a.exe", "-x")}
