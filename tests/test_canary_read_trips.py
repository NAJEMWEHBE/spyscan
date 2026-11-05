"""Audit #9: a decoy that is only READ must raise the alert the site promises.

Before, a pure read or copy (the actual exfiltration) left hash/size/mtime
untouched, atime "never trips on its own", and the SACL/4663 setup that would
catch reads was reachable from no CLI or UI path. Now:

- ``spyscan canary audit-setup`` prints (never runs) the elevated commands,
  using the locale-independent auditpol GUID and the Everyone SID.
- The collector reads 4663 events for EVERY canary, and a 4663 by another
  program after planting trips the decoy (+8 ALERT). spyscan's own hashing read,
  Defender and Windows Search (from their real install folders) do not trip it.

The Security log is never read here: the audit runner is replaced by fakes.
"""
from __future__ import annotations
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from spyscan import canary, canary_audit, cli, service
from spyscan.collectors import canary as canary_collector
from spyscan.score import score_fact

T0 = 1_800_000_000.0                      # 2027-01-15T08:00:00Z
AFTER = "2027-01-15T09:00:00.1234567Z"
BEFORE = "2027-01-15T07:00:00.0000000Z"


def _planted(tmp_path):
    state = tmp_path / "s.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0,
                  names=["passwords.txt", "payroll.csv"])
    return state, str(tmp_path / "d" / "passwords.txt"), str(tmp_path / "d" / "payroll.csv")


def _events(monkeypatch, events):
    asked = []

    def fake(paths, since=None):
        asked.append(list(paths))
        return [dict(e) for e in events]

    monkeypatch.setattr(canary_audit, "gather", fake)
    return asked


def _ev(path, proc, when=AFTER, mask="0x1"):
    return {"object_name": path, "process_name": proc, "time": when, "access_mask": mask}


def test_a_foreign_read_trips_an_unchanged_decoy_and_alerts(tmp_path, monkeypatch):
    state, pw, _ = _planted(tmp_path)
    _events(monkeypatch, [_ev(pw, r"C:\Users\v\AppData\Roaming\upd\upd.exe")])
    facts = canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 3600))
    assert [f.attrs["path"] for f in facts] == [pw]
    f = facts[0]
    assert any("read" in r for r in f.attrs["reasons"])
    assert f.observed["accessed_by"] == [r"C:\Users\v\AppData\Roaming\upd\upd.exe"]
    assert score_fact(f)["bucket"] == "ALERT"


def test_audit_is_asked_about_every_canary_not_only_tripped_ones(tmp_path, monkeypatch):
    state, pw, pay = _planted(tmp_path)
    asked = _events(monkeypatch, [])
    canary_collector.gather(state_path=state, now=T0 + 60)
    assert sorted(asked[0]) == sorted([pw, pay])


@pytest.mark.parametrize("proc", sorted({sys.executable,
                                         getattr(sys, "_base_executable", sys.executable)}))
def test_spyscans_own_hashing_read_does_not_trip(tmp_path, monkeypatch, proc):
    state, pw, _ = _planted(tmp_path)
    _events(monkeypatch, [_ev(pw, proc.upper())])
    assert canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 60)) == []


@pytest.mark.parametrize("proc", [
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2409.6-0\MsMpEng.exe",
    r"C:\Windows\System32\SearchProtocolHost.exe",
    r"C:\Windows\System32\SearchIndexer.exe",
])
def test_defender_and_windows_search_reads_do_not_trip(tmp_path, monkeypatch, proc):
    state, pw, _ = _planted(tmp_path)
    _events(monkeypatch, [_ev(pw, proc)])
    assert canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 60)) == []


def test_a_lookalike_system_reader_outside_its_folder_still_trips(tmp_path, monkeypatch):
    state, pw, _ = _planted(tmp_path)
    _events(monkeypatch, [_ev(pw, r"C:\Users\v\AppData\Local\Temp\MsMpEng.exe")])
    assert len(canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 60))) == 1


def test_events_from_before_planting_are_ignored(tmp_path, monkeypatch):
    state, pw, _ = _planted(tmp_path)
    _events(monkeypatch, [_ev(pw, r"C:\x\old.exe", when=BEFORE)])
    assert canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 60)) == []


def test_an_attribute_only_access_does_not_trip(tmp_path, monkeypatch):
    state, pw, _ = _planted(tmp_path)
    _events(monkeypatch, [_ev(pw, r"C:\x\lister.exe", mask="0x80")])   # ReadAttributes
    assert canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 60)) == []


def test_canary_status_reports_a_read(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    d = tmp_path / "decoys"
    assert cli.main(["canary", "deploy", "--into", str(d)]) == 0
    pw = next(str(p) for p in d.iterdir())
    _events(monkeypatch, [_ev(pw, r"C:\x\snoop.exe", when="2099-01-01T00:00:00Z")])
    capsys.readouterr()
    assert cli.main(["canary", "status"]) == 1
    out = capsys.readouterr().out
    assert "TRIPPED" in out and "snoop.exe" in out


# --- audit-setup ---------------------------------------------------------------

def test_audit_setup_prints_commands_for_tracked_decoys_and_runs_nothing(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    d = tmp_path / "decoys"
    assert cli.main(["canary", "deploy", "--into", str(d)]) == 0
    capsys.readouterr()

    def no_run(*a, **k):
        raise AssertionError("audit-setup must not run anything")

    monkeypatch.setattr(subprocess, "run", no_run)
    monkeypatch.setattr(subprocess, "Popen", no_run)
    assert cli.main(["canary", "audit-setup"]) == 0
    out = capsys.readouterr().out
    for p in d.iterdir():
        assert str(p) in out
    assert "{0CCE921D-69AE-11D9-BED3-505054503030}" in out


def test_audit_setup_without_decoys_says_deploy_first(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    assert cli.main(["canary", "audit-setup"]) == 1
    assert "canary deploy" in capsys.readouterr().out


def test_audit_commands_do_not_depend_on_the_windows_language():
    txt = canary_audit.enable_audit_commands([r"C:\d\passwords.txt"])
    assert '"File System"' not in txt          # localized subcategory name
    assert "'Everyone'" not in txt             # localized account name
    assert "S-1-1-0" in txt
    assert "-Audit" in txt                     # keep any existing SACL entries


_PARSE = r"""
$src = [Console]::In.ReadToEnd(); $t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$t, [ref]$e)
"errors=$($e.Count)"
$ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
  ForEach-Object { "cmd=" + $_.GetCommandName() }
"""


@pytest.mark.skipif(shutil.which("powershell") is None, reason="needs Windows PowerShell")
def test_audit_commands_parse_cleanly():
    # PARSE ONLY: nothing is run, no audit policy or SACL is touched
    script = canary_audit.enable_audit_commands([r"C:\d\passwords.txt"])
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PARSE],
                         input=script.encode("utf-8"), capture_output=True, timeout=60)
    text = out.stdout.decode("utf-8", errors="replace")
    assert "errors=0" in text
    cmds = sorted({ln[4:].strip().lower() for ln in text.splitlines() if ln.startswith("cmd=")})
    assert cmds == ["auditpol", "get-acl", "new-object", "set-acl"]


# --- the site and README promise what the code does -----------------------------

ROOT = Path(__file__).resolve().parents[1]


def test_site_and_readme_tie_read_alerts_to_audit_setup():
    for doc in (ROOT / "docs" / "index.html", ROOT / "README.md"):
        text = doc.read_text(encoding="utf-8")
        assert "canary audit-setup" in text, doc.name
    site = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert "that behavior alone raises an alert" not in site


# --- the packaged app has no CLI: the same commands are reachable from the UI ---

def _app_client(tmp_path):
    from spyscan.app import server
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    c = app.test_client()
    c.environ_base["HTTP_X_SPYSCAN_TOKEN"] = app.config["SPYSCAN_TOKEN"]
    return c


def test_app_serves_the_audit_setup_commands(tmp_path, monkeypatch):
    c = _app_client(tmp_path)
    d = c.get("/api/canary/audit-setup").get_json()
    assert d == {"deployed": False, "commands": ""}
    state = tmp_path / "config" / "canary_state.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0, names=["passwords.txt"])
    d = c.get("/api/canary/audit-setup").get_json()
    assert d["deployed"] is True
    assert str(tmp_path / "d" / "passwords.txt") in d["commands"]
    assert canary_audit.FILE_SYSTEM_SUBCATEGORY in d["commands"]


def test_app_status_names_who_read_a_decoy(tmp_path, monkeypatch):
    state = tmp_path / "config" / "canary_state.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0, names=["passwords.txt"])
    pw = str(tmp_path / "d" / "passwords.txt")
    _events(monkeypatch, [_ev(pw, r"C:\x\snoop.exe", when="2099-01-01T00:00:00Z")])
    d = _app_client(tmp_path).get("/api/canary/status").get_json()
    assert d["tripped"] == 1
    assert d["canaries"][0]["accessed_by"] == [r"C:\x\snoop.exe"]
