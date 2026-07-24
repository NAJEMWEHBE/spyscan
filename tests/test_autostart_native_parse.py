"""Native autostart collector -- pure parse + design-invariant tests.

The gather() edge (winreg / filesystem / WMI-via-PowerShell) is Windows-live and
integration-tested by hand; these lock the PURE half and the two decisions the
collector's correctness hinges on:
  1. signing is left UNKNOWN (verified=None), never False -> no false "unsigned" penalty;
  2. it steps aside when a user autorunsc exists -> no double-reporting.
"""
from __future__ import annotations
import pytest

from spyscan.collectors import COLLECTORS, autostart_native as an
from spyscan.collectors.autostart_native import (
    _exe_from_command, _parse_run, _parse_winlogon, _parse_startup, _parse_wmi, parse,
)
from spyscan.score import score_fact


# --- registration -----------------------------------------------------------

def test_collector_registered():
    assert "autostart_native" in {c.name for c in COLLECTORS}


# --- _exe_from_command ------------------------------------------------------

@pytest.mark.parametrize("cmd,expected", [
    ('"C:\\Program Files\\App\\a.exe" -x', "C:\\Program Files\\App\\a.exe"),
    ("C:\\Windows\\system32\\userinit.exe,", "C:\\Windows\\system32\\userinit.exe"),
    ("rundll32.exe foo,Bar", "rundll32.exe"),
    ("C:\\tools\\noext -flag", "C:\\tools\\noext"),
    ("", ""),
    ('"unterminated', "unterminated"),
])
def test_exe_from_command(cmd, expected):
    assert _exe_from_command(cmd) == expected


# --- Run keys ---------------------------------------------------------------

def test_parse_run_native_and_wow64_location_and_shape():
    rows = [
        ("HKCU", "native", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "Updater", r'"C:\Users\a\upd.exe" /bg'),
        ("HKLM", "wow64", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "Legacy32", r"C:\Windows\Temp\x.exe"),
    ]
    facts = _parse_run(rows)
    assert len(facts) == 2
    f0 = facts[0]
    assert f0.kind == "autostart"
    assert f0.attack_id == "T1547.001"
    assert f0.attrs["entry"] == "Updater"
    assert f0.attrs["image_path"] == r"C:\Users\a\upd.exe"
    assert f0.attrs["launch_string"] == r'"C:\Users\a\upd.exe" /bg'
    assert f0.attrs["location"].endswith(r"CurrentVersion\Run")
    assert "(WOW64)" not in f0.attrs["location"]
    # the WOW64 view is labeled, and a temp image flips from_temp
    assert facts[1].attrs["location"].endswith("(WOW64)")
    assert facts[1].attrs["from_temp"] is True
    assert f0.attrs["from_temp"] is False


def test_run_facts_leave_signing_unknown_not_false():
    rows = [("HKCU", "native", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             "X", r"C:\a\x.exe")]
    a = _parse_run(rows)[0].attrs
    # UNKNOWN, not unsigned -- the pipeline enrich pass fills these in for suspicious ones
    assert a["verified"] is None
    assert a["signed"] is None
    assert a["source"] == "native"


def test_wow64_view_swept_for_hklm_only_not_hkcu():
    """HKCU\\SOFTWARE is SHARED under WOW64, HKLM\\SOFTWARE is REDIRECTED.

    Sweeping a second (WOW64) view of HKCU re-reads the same physical key, and since the
    view name lands in `location` -- which feeds entity_key -- every user autostart would
    be reported TWICE under two distinct keys. Measured before the fix: 17 facts for 10
    real autostarts. HKLM must keep both views: a 32-bit implant genuinely hides in the
    physically separate Wow6432Node key.
    https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys
    """
    assert an._VIEWS_BY_SCOPE["HKCU"] == ("native",)
    assert an._VIEWS_BY_SCOPE["HKLM"] == ("native", "wow64")


@pytest.mark.integration
def test_gather_run_reports_each_hkcu_autostart_once():
    """Live regression for the duplicate above: no HKCU value may appear under two views."""
    rows = an._gather_run()
    assert not [r for r in rows if r[0] == "HKCU" and r[1] != "native"]
    hkcu = [(scope, key, vname) for scope, _v, key, vname, _d in rows if scope == "HKCU"]
    assert len(hkcu) == len(set(hkcu)), "same HKCU value gathered more than once"
    facts = _parse_run(rows)
    assert len({f.entity_key for f in facts}) == len(facts)


def test_run_entity_keys_distinct_per_image():
    rows = [
        ("HKCU", "native", r"SOFTWARE\...\Run", "Dup", r"C:\a\one.exe"),
        ("HKCU", "native", r"SOFTWARE\...\Run", "Dup", r"C:\a\two.exe"),
    ]
    facts = _parse_run(rows)
    assert len({f.entity_key for f in facts}) == 2


# --- Winlogon ---------------------------------------------------------------

def test_parse_winlogon_attack_and_location():
    facts = _parse_winlogon([("HKLM", "Userinit", r"C:\Windows\system32\userinit.exe,")])
    assert len(facts) == 1
    f = facts[0]
    assert f.attack_id == "T1547.004"
    assert f.attrs["entry"] == "Userinit"
    assert f.attrs["image_path"] == r"C:\Windows\system32\userinit.exe"
    assert "Winlogon" in f.attrs["location"]


def test_parse_winlogon_append_hijack_mints_payload_as_own_entity():
    # the classic T1547.004 append hijack: payload must get its OWN key/image,
    # not collapse into the stock binary's fact (ADR 0002 rule 2: split)
    benign = _parse_winlogon(
        [("HKLM", "Userinit", r"C:\Windows\system32\userinit.exe,")])
    hijacked = _parse_winlogon(
        [("HKLM", "Userinit",
          r"C:\Windows\system32\userinit.exe,C:\ProgramData\svchost\evil.exe")])
    assert len(benign) == 1 and len(hijacked) == 2
    keys_b = {f.entity_key for f in benign}
    keys_h = {f.entity_key for f in hijacked}
    assert keys_b < keys_h                      # stock fact unchanged...
    (new_key,) = keys_h - keys_b                # ...payload is a NEW entity
    payload = next(f for f in hijacked if f.entity_key == new_key)
    assert payload.attrs["image_path"] == r"C:\ProgramData\svchost\evil.exe"
    # and the stock fact's attrs did not change (no phantom 'changed')
    stock_b = benign[0]
    stock_h = next(f for f in hijacked if f.entity_key == stock_b.entity_key)
    assert stock_b == stock_h


# --- Startup folders --------------------------------------------------------

def test_parse_startup_uses_lnk_target_as_image():
    rows = [("user", r"C:\Users\a\...\Startup", "tool.lnk",
             r"C:\Users\a\...\Startup\tool.lnk",
             r"C:\Program Files\Tool\tool.exe", "--tray")]
    f = _parse_startup(rows)[0]
    assert f.attack_id == "T1547.001"
    assert f.attrs["image_path"] == r"C:\Program Files\Tool\tool.exe"
    assert f.attrs["launch_string"] == r"C:\Program Files\Tool\tool.exe --tray"
    assert f.attrs["shortcut"] == r"C:\Users\a\...\Startup\tool.lnk"
    assert f.attrs["location"].startswith("Startup folder (user)")


def test_parse_startup_per_user_benign_lnk_is_not_from_temp():
    # the per-user Startup folder is ALWAYS under AppData\Roaming; a benign
    # shortcut to Program Files must not fire the tempish signal
    folder = r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    rows = [("user", folder, "ok.lnk", folder + r"\ok.lnk",
             r"C:\Program Files\Ok\ok.exe", "")]
    assert _parse_startup(rows)[0].attrs["from_temp"] is False


def test_parse_startup_common_lnk_targeting_temp_is_from_temp():
    # inverse case: a common-folder shortcut whose TARGET lives in %TEMP% is the
    # real signal and must fire
    folder = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    rows = [("common", folder, "upd.lnk", folder + r"\upd.lnk",
             r"C:\Users\a\AppData\Local\Temp\evil.exe", "")]
    assert _parse_startup(rows)[0].attrs["from_temp"] is True


def test_parse_startup_unresolved_lnk_falls_back_to_container_no_false_temp():
    folder = r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    rows = [("user", folder, "x.lnk", folder + r"\x.lnk", "", "")]
    f = _parse_startup(rows)[0]
    assert f.attrs["image_path"] == folder + r"\x.lnk"
    assert f.attrs["from_temp"] is False        # degraded signal, not a false one
    assert f.attrs["shortcut"] == ""


# --- WMI subscriptions ------------------------------------------------------

def test_parse_wmi_both_consumer_classes():
    raw = {
        "cmdline": (b"Name,ExecutablePath,CommandLineTemplate\r\n"
                    b'"Persist","","powershell -enc AAAA"\r\n'),
        "script": (b"Name,ScriptingEngine,ScriptFileName\r\n"
                   b'"ScriptPersist","VBScript","C:\\x\\s.vbs"\r\n'),
    }
    facts = _parse_wmi(raw)
    assert len(facts) == 2
    assert all(f.attack_id == "T1546.003" for f in facts)
    cmd = next(f for f in facts if f.attrs["wmi_class"] == "CommandLineEventConsumer")
    assert cmd.attrs["entry"] == "Persist"
    assert cmd.attrs["image_path"] == "powershell"          # derived from the template
    assert "powershell -enc AAAA" == cmd.attrs["launch_string"]
    scr = next(f for f in facts if f.attrs["wmi_class"] == "ActiveScriptEventConsumer")
    assert scr.attrs["entry"] == "ScriptPersist"


def test_parse_wmi_empty_is_no_facts():
    assert _parse_wmi({}) == []
    assert _parse_wmi({"cmdline": b"", "script": b""}) == []


# --- top-level parse + empties ----------------------------------------------

def test_parse_empty_dict_is_empty():
    assert parse({}) == []
    assert parse(None) == []


# --- design invariant: unknown-signing native autostart is NOT scored unsigned ---

def test_native_autostart_not_penalized_as_unsigned():
    # a temp-resident native autostart with UNKNOWN signing must not collect the
    # "unsigned / unverified binary" penalty (that is reserved for verified is False).
    rows = [("HKCU", "native", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             "T", r"C:\Users\a\AppData\Local\Temp\p.exe")]
    fact = _parse_run(rows)[0]
    assert fact.attrs["from_temp"] is True          # the temp signal DID fire
    r = score_fact(fact)
    assert not any("unsigned" in why for why in r["reasons"]), r["reasons"]


# --- design invariant: steps aside when a user autorunsc exists -------------

def test_gather_steps_aside_when_autorunsc_available(monkeypatch):
    monkeypatch.setattr(an, "autorunsc_available", lambda: True)
    assert an.gather() == {}      # no native sweep -> autoruns covers it, no double-report
