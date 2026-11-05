"""Audit #12: tasks and drivers must not vanish on non-English Windows.

`schtasks /fo csv /v` and `driverquery /fo csv /v` print LOCALIZED headers, so on
Arabic, French or German Windows 'TaskName' / 'Module Name' never appear and the
scan silently gets zero tasks and drivers. Their output is also in the OEM code
page, not UTF-8. When the English header is missing, spyscan now asks PowerShell
(whose property names are English on every locale) through the data-safe adapter,
and console output is decoded with the OEM code page when it is not UTF-8.
These tests sit at the subprocess boundary; nothing touches the real system.
"""
from __future__ import annotations
import shutil
import subprocess
import types

import pytest

from spyscan.collectors import drivers, services_tasks
from spyscan.collectors import base

FR_TASKS = ('"Nom de l\'h\u00f4te","Nom de la t\u00e2che","Prochaine ex\u00e9cution"\r\n'
            '"PC","\\Mise \u00e0 jour","N/A"\r\n').encode("cp850")
FR_DRIVERS = ('"Nom du module","Nom complet","Description"\r\n'
              '"monflt","Filtre","Filtre"\r\n').encode("cp850")
PS_TASKS = ('"TaskName","Task To Run","Author","Run As User","Scheduled Task State",'
            '"Schedule Type","Status","Last Run Time"\r\n'
            '"\\Mise \u00e0 jour","C:\\ProgramData\\m\\m.exe /q","X","SYSTEM","Enabled",'
            '"Logon","Ready",""\r\n').encode("utf-8")
PS_DRIVERS = ('"Module Name","Display Name","Driver Type","Start Mode","State","Status",'
              '"Link Date","Path"\r\n'
              '"monflt","Filtre","Kernel Driver","Auto","Running","OK","",'
              '"C:\\WINDOWS\\system32\\drivers\\monflt.sys"\r\n').encode("utf-8")


def _fake(monkeypatch, console_out: bytes, ps_out: bytes):
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        out = ps_out if args[0] == "powershell" else console_out
        return types.SimpleNamespace(stdout=out, stderr=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_localized_schtasks_falls_back_to_get_scheduledtask(monkeypatch):
    calls = _fake(monkeypatch, FR_TASKS, PS_TASKS)
    raw = services_tasks.gather()
    assert any(a[0] == "powershell" and "Get-ScheduledTask" in a[-1] for a in calls)
    tasks = [f for f in services_tasks.parse(raw) if f.kind == "scheduled_task"]
    assert [f.attrs["name"] for f in tasks] == ["\\Mise \u00e0 jour"]
    assert tasks[0].attrs["task_to_run"] == "C:\\ProgramData\\m\\m.exe /q"


def test_english_schtasks_needs_no_fallback(monkeypatch):
    en = b'"HostName","TaskName","Task To Run"\r\n"PC","\\T","c:\\t.exe"\r\n'
    calls = _fake(monkeypatch, en, b"")
    services_tasks.gather()
    assert not any("Get-ScheduledTask" in a[-1] for a in calls)


def test_localized_driverquery_falls_back_to_cim(monkeypatch):
    calls = _fake(monkeypatch, FR_DRIVERS, PS_DRIVERS)
    facts = drivers.parse(drivers.gather())
    assert any(a[0] == "powershell" and "Win32_SystemDriver" in a[-1] for a in calls)
    assert [f.attrs["module"] for f in facts] == ["monflt"]
    assert facts[0].attrs["path"].endswith("monflt.sys")


def test_english_driverquery_needs_no_fallback(monkeypatch):
    en = b'"Module Name","Display Name","Path"\r\n"x","X","c:\\x.sys"\r\n'
    calls = _fake(monkeypatch, en, b"")
    drivers.gather()
    assert all(a[0] != "powershell" for a in calls)


def test_console_output_in_the_oem_code_page_is_decoded(monkeypatch):
    monkeypatch.setattr(base, "_oem_codepage", lambda: 850)
    assert base.decode_console("\u00e9t\u00e9".encode("cp850")) == "\u00e9t\u00e9"
    assert base.decode_console("\u00e9t\u00e9".encode("utf-8")) == "\u00e9t\u00e9"
    assert base.decode_console(b"\xef\xbb\xbfplain") == "plain"


_PARSE = r"""
$src = [Console]::In.ReadToEnd(); $t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$t, [ref]$e)
"errors=$($e.Count)"
"""


@pytest.mark.skipif(shutil.which("powershell") is None, reason="needs Windows PowerShell")
@pytest.mark.parametrize("script", [services_tasks.TASKS_FALLBACK, drivers.DRIVERS_FALLBACK])
def test_fallback_scripts_parse(script):
    # PARSE ONLY: the scripts are never run here
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PARSE],
                         input=script.encode("utf-8"), capture_output=True, timeout=60)
    assert "errors=0" in out.stdout.decode("utf-8", errors="replace")
