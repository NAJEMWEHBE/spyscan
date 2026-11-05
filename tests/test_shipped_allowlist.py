"""Audit #7: the shipped allowlist must not blind the scanner for every user.

The default glob  *\\.venv\\scripts\\*  matched ANY folder named .venv, so an
unsigned, parentless, new svchost.exe dropped in AppData\\...\\.venv\\Scripts was
floored to INFO 0. The shipped list is now empty; a dev run from source quiets
only the interpreter's OWN venv, by absolute path, computed at run time.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

from spyscan import service
from spyscan.allowlist import Allowlist
from spyscan.facts import Fact
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher

REPO = Path(__file__).resolve().parents[1]


def test_shipped_allowlist_has_no_path_globs():
    data = json.loads((REPO / "config" / "allowlist.json").read_text(encoding="utf-8"))
    assert data["path_globs"] == []


def test_implant_in_a_fake_venv_folder_is_not_floored():
    al = Allowlist.load(REPO / "config" / "allowlist.json")
    implant = Fact("processes", "processes::svchost.exe::x", "process", "svchost.exe (pid 9)",
                   {"exe": r"C:\Users\v\AppData\Roaming\Microsoft\.venv\Scripts\svchost.exe",
                    "from_temp": True}, None, {"parents": [""]})
    anchor = Fact("processes", "processes::anchor", "process", "anchor", {"exe": r"c:\a.exe"})
    out = build_findings([anchor], [anchor, implant], IOCMatcher(), allowlist=al,
                         signer=lambda p: {"signed": False, "verified": False,
                                           "trusted_ms": False, "signer": ""},
                         log=lambda *a: None)
    fd = next(f for f in out if f.fact.entity_key == implant.entity_key)
    assert fd.bucket == "ALERT"


def test_dev_run_quiets_only_its_own_venv(monkeypatch, tmp_path):
    venv = tmp_path / "proj" / ".venv"
    monkeypatch.setattr(sys, "prefix", str(venv))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "Python314"))
    monkeypatch.setattr(service, "is_frozen", lambda: False)
    globs = service.dev_self_globs()
    assert globs == [str(venv / "Scripts").lower() + "\\*"]
    al = Allowlist(path_globs=globs)
    assert al.matches({"exe": str(venv / "Scripts" / "python.exe")})[0] is True
    other = r"C:\Users\v\AppData\Roaming\Microsoft\.venv\Scripts\svchost.exe"
    assert al.matches({"exe": other})[0] is False


def test_no_self_glob_outside_a_venv_or_when_frozen(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "Python314"))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "Python314"))
    monkeypatch.setattr(service, "is_frozen", lambda: False)
    assert service.dev_self_globs() == []
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "proj" / ".venv"))
    monkeypatch.setattr(service, "is_frozen", lambda: True)
    assert service.dev_self_globs() == []


def test_run_scan_applies_the_dev_self_glob(monkeypatch, tmp_path):
    venv = tmp_path / "proj" / ".venv"
    monkeypatch.setattr(sys, "prefix", str(venv))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "Python314"))
    monkeypatch.setattr(service, "is_frozen", lambda: False)
    me = Fact("processes", "processes::python.exe::me", "process", "python.exe",
              {"exe": str(venv / "Scripts" / "python.exe"), "from_temp": True}, None,
              {"parents": [""]})
    ind = tmp_path / "ind"
    ind.mkdir()
    db = tmp_path / "b.db"
    service.run_baseline(tmp_path, db, collect=lambda ctx: [
        Fact("processes", "processes::seed::seed", "process", "seed", {})], log=lambda *a: None)
    res = service.run_scan(tmp_path, db, collect=lambda ctx: [me], ind=ind,
                           log=lambda *a: None)
    assert res["summary"]["allowlisted"] == 1
