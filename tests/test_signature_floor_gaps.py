"""Audit #2 + #4: every autostart gets a signature check, and the Microsoft-signed
floor judges what an entry RUNS, not just the host binary that runs it.

#2: native autostart facts carry their image in ``image_path``, which the
    enrichment pass never read, so no native autostart was ever signature-checked.
#4: a verified-Microsoft host (powershell, rundll32...) launching an AppData
    payload was floored to INFO 0, and any signer merely CONTAINING "microsoft"
    (incl. the Hardware Compatibility Publisher that signs third-party drivers)
    counted as Microsoft.
"""
from __future__ import annotations
import pytest

from spyscan.allowlist import Allowlist
from spyscan.enrich.signature import parse_status
from spyscan.facts import Fact
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher

MS = {"signed": True, "verified": True, "trusted_ms": True,
      "signer": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}
UNSIGNED = {"signed": False, "verified": False, "trusted_ms": False, "signer": ""}
ANCHOR = Fact("processes", "processes::anchor", "process", "anchor", {"exe": r"c:\a.exe"})


def _finding(fact, sig):
    calls = []

    def signer(path):
        calls.append(path)
        return dict(sig)

    out = build_findings([ANCHOR], [ANCHOR, fact], IOCMatcher(), signer=signer,
                         allowlist=Allowlist(), log=lambda *a: None)
    return next(f for f in out if f.fact.entity_key == fact.entity_key), calls


# --- #2 ----------------------------------------------------------------------

def test_native_autostart_is_signature_checked_and_unsigned_appdata_run_key_alerts():
    img = r"C:\Users\v\AppData\Roaming\spy\spy.exe"
    f = Fact("autostart_native", "autostart_native::spy", "autostart", "Spy",
             {"entry": "Spy", "image_path": img, "launch_string": img,
              "from_temp": True, "verified": None, "signed": None})
    fd, calls = _finding(f, UNSIGNED)
    assert calls == [img]
    assert fd.bucket == "ALERT" and fd.score == 8


# --- #4: what the entry runs ----------------------------------------------------

def test_ms_powershell_running_an_appdata_script_is_not_floored():
    f = Fact("autoruns", "autoruns::upd", "autostart", "Updater",
             {"entry": "Updater",
              "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              "launch_string": r"powershell.exe -w hidden -ep bypass -f C:\Users\v\AppData\Roaming\upd\a.ps1",
              "from_temp": True, "verified": True, "signer": "Microsoft Windows"})
    fd, _ = _finding(f, MS)
    assert "allowlisted: Microsoft-signed" not in fd.reasons
    assert fd.bucket == "REVIEW" and fd.score >= 6


@pytest.mark.parametrize("launch", [
    r"C:\Windows\System32\rundll32.exe C:\ProgramData\x\x.dll,Start",
    r"C:\Windows\System32\mshta.exe vbscript:Execute(...)",
    r"C:\Windows\System32\cmd.exe /c start C:\ProgramData\x\x.bat",
    r"wscript.exe //B C:\ProgramData\x\x.vbs",
])
def test_ms_script_or_proxy_host_with_a_payload_is_not_floored(launch):
    host = launch.split()[0]
    al = Allowlist()
    ok, _ = al.matches({"image_path": host, "launch_string": launch,
                        "verified": True, "signer": "Microsoft Windows"})
    assert ok is False


def test_ms_binary_whose_launch_string_points_into_appdata_is_not_floored():
    ok, _ = Allowlist().matches({
        "image_path": r"C:\Windows\System32\conhost.exe",
        "launch_string": r"C:\Windows\System32\conhost.exe C:\Users\v\AppData\Local\Temp\p.bin",
        "verified": True, "signer": "Microsoft Windows"})
    assert ok is False


def test_running_powershell_with_arguments_is_not_floored_but_bare_one_is():
    def proc(cmdline):
        return Fact("processes", "processes::powershell.exe::" + cmdline, "process",
                    "powershell.exe (pid 9)",
                    {"exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "from_temp": False}, None,
                    {"parents": ["explorer.exe"], "cmdlines": [cmdline]})
    fd, _ = _finding(proc("powershell.exe -enc SQBFAFgA"), MS)
    assert "allowlisted: Microsoft-signed" not in fd.reasons
    fd, _ = _finding(proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"), MS)
    assert fd.reasons == ["allowlisted: Microsoft-signed"]


def test_plain_ms_autostart_still_floors():
    ok, why = Allowlist().matches({
        "image_path": r"C:\WINDOWS\system32\SecurityHealthSystray.exe",
        "launch_string": r"%windir%\system32\SecurityHealthSystray.exe",
        "verified": True, "signer": "Microsoft Windows"})
    assert ok and why == "allowlisted: Microsoft-signed"


# --- #4: who counts as Microsoft -----------------------------------------------

@pytest.mark.parametrize("signer", [
    "Microsoft Windows",
    "Microsoft Corporation",
    "Microsoft Windows Publisher",
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
])
def test_real_microsoft_signers_floor(signer):
    assert Allowlist().matches({"verified": True, "signer": signer})[0] is True


@pytest.mark.parametrize("signer", [
    "CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, "
    "L=Redmond, S=Washington, C=US",
    "Microsoft Windows Hardware Compatibility Publisher",
    "Microsoft 3rd Party Application Component",
    "CN=Not Microsoft Ltd, O=Not Microsoft Ltd",
    "Microsoftware Solutions Inc",
])
def test_lookalike_or_third_party_microsoft_signers_do_not_floor(signer):
    assert Allowlist().matches({"verified": True, "signer": signer})[0] is False


def test_authenticode_trusted_ms_needs_an_exact_microsoft_subject():
    hcp = ("Valid|CN=Microsoft Windows Hardware Compatibility Publisher, "
           "O=Microsoft Corporation, L=Redmond, S=Washington, C=US")
    assert parse_status(hcp)["trusted_ms"] is False
    real = "Valid|CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
    assert parse_status(real)["trusted_ms"] is True
