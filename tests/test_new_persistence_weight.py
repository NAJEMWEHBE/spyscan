"""Audit #5: new persistence since the baseline must surface, and be checked.

A new service in Program Files, a new scheduled task or a new driver scored
+3 = INFO (hidden) and was never signature-checked -- exactly how commercial
PC-monitoring and stalkerware install. New persistence now weighs 4 (REVIEW on
its own), every persistence kind is an enrichment candidate, and service/task
command lines are reduced to the program they run before probing.
"""
from __future__ import annotations
import pytest

from spyscan.allowlist import Allowlist
from spyscan.facts import Fact
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher
from spyscan.score import score_fact

UNSIGNED = {"signed": False, "verified": False, "trusted_ms": False, "signer": ""}
MS = {"signed": True, "verified": True, "trusted_ms": True, "signer": "Microsoft Windows"}
ANCHOR = Fact("processes", "processes::anchor", "process", "anchor", {"exe": r"c:\a.exe"})


def _run(fact, sig):
    calls = []

    def signer(p):
        calls.append(p)
        return dict(sig)

    out = build_findings([ANCHOR], [ANCHOR, fact], IOCMatcher(), signer=signer,
                         allowlist=Allowlist(), log=lambda *a: None)
    return next(f for f in out if f.fact.entity_key == fact.entity_key), calls


SERVICE = Fact("services_tasks", "services_tasks::service::mon", "service", "service: mon",
               {"name": "mon", "path": r'"C:\Program Files (x86)\Monitor\mon.exe" -k run',
                "start_mode": "Auto", "from_temp": False})
TASK = Fact("services_tasks", r"services_tasks::task::\mon", "scheduled_task", "task: mon",
            {"name": r"\mon", "task_to_run": r"C:\ProgramData\mon\mon.exe /silent",
             "from_temp": False})
DRIVER = Fact("drivers", "drivers::monflt", "driver", "driver: monflt",
              {"module": "monflt", "path": r"C:\Windows\System32\drivers\monflt.sys",
               "from_temp": False})


@pytest.mark.parametrize("fact,probed", [
    (SERVICE, r"C:\Program Files (x86)\Monitor\mon.exe"),
    (TASK, r"C:\ProgramData\mon\mon.exe"),
    (DRIVER, r"C:\Windows\System32\drivers\monflt.sys"),
])
def test_new_unsigned_persistence_is_probed_and_reviewed(fact, probed):
    fd, calls = _run(fact, UNSIGNED)
    assert calls == [probed]
    assert fd.bucket == "REVIEW" and fd.score == 6       # +4 new persistence, +2 unsigned


def test_new_microsoft_signed_service_stays_quiet():
    fd, _ = _run(SERVICE, MS)
    assert fd.bucket == "INFO"


@pytest.mark.parametrize("kind", ["autostart", "service", "scheduled_task", "driver"])
def test_new_persistence_alone_is_review(kind):
    r = score_fact(Fact("c", "c::x", kind, "x", {"is_new": True}))
    assert r["score"] == 4 and r["bucket"] == "REVIEW"
    assert "+4 new persistence entry since baseline" in r["reasons"]


@pytest.mark.parametrize("kind", ["process", "connection", "device_use"])
def test_new_ephemeral_fact_keeps_the_old_weight(kind):
    r = score_fact(Fact("c", "c::x", kind, "x", {"is_new": True, "remote_ip": "8.8.8.8"}))
    assert r["score"] == 3
