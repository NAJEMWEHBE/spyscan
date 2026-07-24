# tests/test_canary_collector.py
"""UNIT 3 - the canary trip wired as a spyscan collector.

gather() loads canary_state.json (if absent -> []) and runs canary.check +
best-effort audit; parse() emits a Fact(kind="canary_trip", ...) ONLY for
tripped canaries. A non-deployed system adds zero facts (zero noise).
"""
from pathlib import Path

from spyscan.collectors import canary as canary_collector
from spyscan.collectors import COLLECTORS
from spyscan import canary

T0 = 1_700_000_000.0


def test_collector_is_registered():
    from spyscan.collectors.canary import CanaryCollector
    reg = [c for c in COLLECTORS if isinstance(c, CanaryCollector)]
    assert len(reg) == 1
    assert reg[0].name == "canary"


def test_no_state_yields_no_facts(tmp_path):
    # nothing deployed -> gather returns [] -> parse returns [] -> zero noise
    rows = canary_collector.gather(state_path=tmp_path / "absent.json", now=T0)
    assert rows == []
    assert canary_collector.parse(rows) == []


def test_untouched_canaries_emit_no_facts(tmp_path):
    state = tmp_path / "s.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0,
                  names=["passwords.txt"])
    rows = canary_collector.gather(state_path=state, now=T0 + 60)
    facts = canary_collector.parse(rows)
    # check ran (rows non-empty) but nothing tripped -> no canary_trip facts
    assert facts == []


def test_tripped_canary_emits_fact(tmp_path):
    state = tmp_path / "s.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0,
                  names=["crypto_wallet_seed.txt"])
    victim = next((tmp_path / "d").glob("crypto_wallet_seed.txt"))
    victim.write_text("STOLEN", encoding="utf-8")
    import os
    os.utime(victim, (T0 + 500, T0 + 500))

    rows = canary_collector.gather(state_path=state, now=T0 + 600)
    facts = canary_collector.parse(rows)
    assert len(facts) == 1
    f = facts[0]
    assert f.kind == "canary_trip"
    assert f.attrs["canary_tripped"] is True
    assert f.attack_id == "T1530"
    assert "crypto_wallet_seed.txt" in f.label
    # carries the human reasons + evidence through
    assert f.attrs.get("reasons")
    assert "hash" in " ".join(f.attrs["reasons"]).lower()
    assert f.entity_key.startswith("canary::")


def test_parse_only_tripped(tmp_path):
    # mixed: one untouched, one tripped -> exactly one fact
    state = tmp_path / "s.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0,
                  names=["passwords.txt", "vpn_credentials.txt"])
    victim = next((tmp_path / "d").glob("vpn_credentials.txt"))
    victim.unlink()  # tripped (missing)
    rows = canary_collector.gather(state_path=state, now=T0 + 100)
    facts = canary_collector.parse(rows)
    assert len(facts) == 1
    assert "vpn_credentials.txt" in facts[0].label


def test_scantime_collector_honors_ctx_root(tmp_path):
    """#02 (the #01 gap, now CLOSED): the scan-time canary read resolves through
    ctx.root.

    The canary collector consumes ScanContext -- gather(ctx) reads
    canary.default_state_path(ctx.root) -- so a scan whose root is X reads
    X/config/canary_state.json. The surface path (service.canary_state_path) and
    the scan-time collector read now resolve through the SAME root, instead of the
    collector free-riding on app_base(). This replaces the earlier #01 pin that
    froze the old app_base-only behavior.
    """
    from spyscan.collectors.base import ScanContext
    from spyscan.collectors.canary import CanaryCollector
    root = tmp_path / "scanroot"
    state = canary.default_state_path(root)                # X/config/canary_state.json
    assert state == root / "config" / "canary_state.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0,
                  names=["passwords.txt"])
    (next((tmp_path / "d").glob("passwords.txt"))).unlink()  # trip via missing

    col = CanaryCollector()
    # scan rooted at X reads X's state -> sees the trip
    facts = col.collect(ScanContext(root=root, now=T0 + 10))
    assert len(facts) == 1
    assert "passwords.txt" in facts[0].label
    # a scan rooted elsewhere reads a different (absent) state -> no trip
    assert col.collect(ScanContext(root=tmp_path / "unrelated", now=T0 + 10)) == []


# --- ADR 0002: tripped canaries must settle; volatile evidence never diffs ----

def test_tripped_canary_settles_across_rescans(tmp_path):
    """The scanner's own hash read must not become next scan's atime 'evidence':
    two consecutive collects of the same tripped canary yield IDENTICAL facts,
    so diff sees changed=0 and a re-baselined trip finally settles."""
    from spyscan.diff import diff_facts
    state = tmp_path / "s.json"
    canary.deploy(targets=[tmp_path / "d"], state_path=state, now=T0,
                  names=["passwords.txt"])
    victim = next((tmp_path / "d").glob("passwords.txt"))
    victim.write_text("STOLEN", encoding="utf-8")

    f1 = canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 100))
    f2 = canary_collector.parse(canary_collector.gather(state_path=state, now=T0 + 200))
    assert len(f1) == 1 and len(f2) == 1
    d = diff_facts(f1, f2)
    assert [len(d["added"]), len(d["removed"]), len(d["changed"])] == [0, 0, 0]


def test_atime_hint_and_evidence_live_in_observed_not_attrs(tmp_path):
    rows = [{
        "path": r"C:\decoys\passwords.txt", "tripped": True,
        "reasons": ["content hash changed (file modified)",
                    "atime advanced (possible read; weak/unreliable - note)"],
        "evidence": {"path": r"C:\decoys\passwords.txt",
                     "sha256": {"was": "a", "now": "b"},
                     "atime": {"was": 1.0, "now": 2.0}},
        "audit": [],
    }]
    f = canary_collector.parse(rows)[0]
    assert "atime" not in f.attrs["evidence"]
    assert all(not r.startswith("atime advanced") for r in f.attrs["reasons"])
    assert f.observed["atime"] == {"was": 1.0, "now": 2.0}
    assert f.observed["atime_hint"]
    assert f.attrs["evidence"]["sha256"] == {"was": "a", "now": "b"}  # reliable stays


def test_accessed_by_is_observed_and_in_label(tmp_path):
    rows = [{
        "path": r"C:\decoys\passwords.txt", "tripped": True,
        "reasons": ["content hash changed (file modified)"],
        "evidence": {},
        "audit": [{"process_name": r"C:\Temp\stealer.exe"}],
    }]
    f = canary_collector.parse(rows)[0]
    assert f.observed["accessed_by"] == [r"C:\Temp\stealer.exe"]
    assert "accessed_by" not in f.attrs        # rolling audit window: not diffed
    assert "stealer.exe" in f.label


def test_audit_regroup_is_case_insensitive(tmp_path, monkeypatch):
    """canary_audit matches ObjectName case-insensitively; the collector regroup
    must too, or the who-touched-it attribution is silently dropped."""
    from spyscan import canary as _canary, canary_audit as _audit
    planted = str(tmp_path / "d" / "passwords.txt")
    monkeypatch.setattr(_canary, "check", lambda sp, now=None: [
        {"path": planted, "tripped": True,
         "reasons": ["content hash changed (file modified)"], "evidence": {}}])
    monkeypatch.setattr(_audit, "gather", lambda paths, since=None: [
        {"object_name": planted.upper(), "process_name": r"C:\Temp\stealer.exe"}])
    rows = canary_collector.gather(state_path=tmp_path / "s.json", now=T0)
    f = canary_collector.parse(rows)[0]
    assert f.observed["accessed_by"] == [r"C:\Temp\stealer.exe"]
    assert "stealer.exe" in f.label
