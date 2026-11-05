"""Audit #18: a "first look" for a PC the user already suspects.

The diff model needs a baseline taken on a trusted machine; the real user
("I think I'm being watched now") would baseline an already-infected PC and
absorb the implant. First look scores the current state on absolute signals,
with no baseline and no "new since baseline":

- every persistence entry not proven Microsoft-signed gets a small base weight,
- a script/proxy host whose payload sits in a user-writable or remote place
  scores on its own,
- persistence is signature-checked, so an unsigned entry reaches REVIEW,
- an ordinary signed third-party entry stays INFO (no firehose).
Nothing here touches the real system: facts and the signer are injected.
"""
from __future__ import annotations
import json
import subprocess

import pytest

from spyscan import cli, service
from spyscan.allowlist import Allowlist
from spyscan.facts import Fact
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher

MS = {"signed": True, "verified": True, "trusted_ms": True, "signer": "CN=Microsoft Windows, O=Microsoft Corporation"}
VENDOR = {"signed": True, "verified": True, "trusted_ms": False, "signer": "CN=Contoso Graphics Inc"}
UNSIGNED = {"signed": False, "verified": False, "trusted_ms": False, "signer": ""}


def _svc(name, path):
    return Fact("services_tasks", f"services_tasks::service::{name}", "service",
                f"service: {name}", {"name": name, "path": path, "from_temp": False})


def _run(name, launch, image, temp=False):
    return Fact("autostart_native", f"autostart_native::{name}", "autostart", name,
                {"entry": name, "image_path": image, "launch_string": launch,
                 "from_temp": temp, "verified": None, "signed": None})


def _triage(facts, sigs):
    calls = []

    def signer(path):
        calls.append(path)
        return dict(sigs.get(path, UNSIGNED))

    out = build_findings([], facts, IOCMatcher(), signer=signer, allowlist=Allowlist(),
                         log=lambda *a: None, first_look=True)
    return {f.fact.entity_key: f for f in out}, calls


def test_unsigned_service_in_program_files_reaches_review_with_no_baseline():
    exe = r"C:\Program Files\Helper\helper.exe"
    by, calls = _triage([_svc("helper", f'"{exe}" -k')], {})
    fd = by["services_tasks::service::helper"]
    assert exe in calls
    assert fd.bucket == "REVIEW" and fd.score == 4
    assert not any("since baseline" in r for r in fd.reasons)


def test_signed_vendor_service_stays_info():
    exe = r"C:\Program Files\Contoso\gfx.exe"
    by, _ = _triage([_svc("gfx", exe)], {exe: VENDOR})
    assert by["services_tasks::service::gfx"].bucket == "INFO"


def test_microsoft_service_is_floored():
    exe = r"C:\Windows\System32\svchost.exe"
    by, _ = _triage([_svc("wuauserv", exe + " -k netsvcs")], {exe: MS})
    assert by["services_tasks::service::wuauserv"].score == 0


def test_powershell_running_an_appdata_script_at_logon_alerts():
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    f = _run("Updater", ps + r" -w hidden -f C:\Users\v\AppData\Roaming\u\a.ps1", ps, temp=True)
    by, _ = _triage([f], {ps: MS})
    fd = by["autostart_native::Updater"]
    assert fd.bucket == "ALERT"
    assert any("script/proxy host" in r for r in fd.reasons)


def test_rundll32_with_a_system_dll_is_not_a_payload():
    rd = r"C:\Windows\System32\rundll32.exe"
    f = _run("Shell", rd + r" C:\Windows\System32\shell32.dll,Control_RunDLL", rd)
    by, _ = _triage([f], {rd: MS})
    fd = by["autostart_native::Shell"]
    assert fd.bucket == "INFO"
    assert not any("script/proxy host" in r for r in fd.reasons)


def test_first_look_has_no_new_or_removed_signals():
    by, _ = _triage([_svc("x", r"C:\Program Files\X\x.exe")], {})
    for fd in by.values():
        assert not fd.fact.attrs.get("is_new")
        assert not fd.fact.attrs.get("removed_since_baseline")


def test_processes_get_no_first_look_base_weight():
    p = Fact("processes", "processes::a::a", "process", "a.exe",
             {"exe": r"C:\Program Files\A\a.exe", "from_temp": False},
             None, {"parents": ["explorer.exe"]})
    by, _ = _triage([p], {r"C:\Program Files\A\a.exe": VENDOR})
    assert by["processes::a::a"].score == 0


# --- service / CLI / app ---------------------------------------------------------

def _facts(ctx):
    return [_svc("helper", r"C:\Program Files\Helper\helper.exe")]


def test_run_triage_needs_no_baseline_and_writes_the_report(tmp_path, monkeypatch):
    monkeypatch.setattr("spyscan.pipeline._default_signer", lambda p: dict(UNSIGNED))
    res = service.run_triage(tmp_path, collect=_facts, log=lambda *a: None)
    assert res["meta"]["mode"] == "first look (no baseline)"
    assert res["summary"]["review"] == 1
    data = json.loads((tmp_path / "runs" / "last_scan.json").read_text(encoding="utf-8"))
    assert data["meta"]["mode"] == "first look (no baseline)"
    assert "first look" in (tmp_path / "runs" / "last_scan.html").read_text(encoding="utf-8")
    assert not (tmp_path / "baseline.db").exists()


def test_cli_triage_prints_actionable_findings(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_collect_all", _facts)
    monkeypatch.setattr("spyscan.pipeline._default_signer", lambda p: dict(UNSIGNED))
    assert cli.main(["triage"]) == 0
    out = capsys.readouterr().out
    assert "first look" in out and "service: helper" in out


def test_app_triage_route(tmp_path, monkeypatch):
    from spyscan.app import server
    monkeypatch.setattr(service, "collect_all", lambda ctx, log=print: _facts(ctx))
    monkeypatch.setattr("spyscan.pipeline._default_signer", lambda p: dict(UNSIGNED))
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    c = app.test_client()
    c.environ_base["HTTP_X_SPYSCAN_TOKEN"] = app.config["SPYSCAN_TOKEN"]
    d = c.post("/api/triage", json={}).get_json()
    assert d["ok"] is True and d["meta"]["mode"] == "first look (no baseline)"
    assert [f["fact"]["label"] for f in d["findings"]] == ["service: helper"]
