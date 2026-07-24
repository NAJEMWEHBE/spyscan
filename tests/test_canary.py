# tests/test_canary.py
"""UNIT 1 - canary tripwire core (deploy / check / clear).

All I/O is injected (targets, state_path, now) so these are deterministic and
hermetic under tmp_path. No real Desktop/Documents are touched here.
"""
import json
import time
from pathlib import Path

from spyscan import canary


# a fixed, monotonic-ish fake clock so planted-at timestamps are predictable
T0 = 1_700_000_000.0


def _deploy(tmp_path, names=None):
    """Deploy into an isolated targets dir under tmp_path."""
    targets = [tmp_path / "decoys"]
    state = tmp_path / "canary_state.json"
    res = canary.deploy(targets=targets, state_path=state, now=T0, names=names)
    return res, state, targets[0]


def test_deploy_writes_state_and_files(tmp_path):
    res, state, ddir = _deploy(tmp_path)
    # state file exists and is valid JSON with one record per planted file
    assert state.exists()
    data = json.loads(state.read_text(encoding="utf-8"))
    assert isinstance(data, dict) and data.get("canaries")
    recs = data["canaries"]
    assert len(recs) >= 1
    # every recorded canary file actually exists on disk and is non-empty
    for r in recs:
        p = Path(r["path"])
        assert p.exists(), f"planted file missing: {p}"
        assert p.stat().st_size > 0
        # state records the required fields
        for field in ("path", "planted_at", "size", "sha256", "mtime", "atime"):
            assert field in r
        assert r["planted_at"] == T0
        assert r["sha256"]  # non-empty hex digest
    # deploy() summary echoes what it planted
    assert res["planted"] == len(recs)
    assert res["state_path"] == str(state)


def test_deploy_has_tempting_bait_content(tmp_path):
    _res, _state, _ddir = _deploy(tmp_path, names=["passwords.txt"])
    f = next((_ddir).glob("passwords.txt"))
    body = f.read_text(encoding="utf-8", errors="replace")
    assert body.strip()  # believable bait, not empty


def test_deploy_never_overwrites_existing_real_file(tmp_path):
    ddir = tmp_path / "decoys"
    ddir.mkdir(parents=True)
    real = ddir / "passwords.txt"
    real.write_text("MY REAL SECRETS - do not touch", encoding="utf-8")
    state = tmp_path / "s.json"
    canary.deploy(targets=[ddir], state_path=state, now=T0, names=["passwords.txt"])
    # the user's real file is untouched
    assert real.read_text(encoding="utf-8") == "MY REAL SECRETS - do not touch"
    # and it was NOT recorded as a canary
    data = json.loads(state.read_text(encoding="utf-8"))
    planted_paths = {Path(r["path"]) for r in data["canaries"]}
    assert real not in planted_paths


def test_check_untouched_canaries_no_trips(tmp_path):
    _res, state, _ddir = _deploy(tmp_path)
    trips = canary.check(state, now=T0 + 60)
    assert all(t["tripped"] is False for t in trips)
    assert trips, "check returned no records at all"


def test_check_reports_trip_on_content_change(tmp_path):
    _res, state, ddir = _deploy(tmp_path, names=["passwords.txt"])
    victim = next(ddir.glob("passwords.txt"))
    # simulate a snoop that reads + rewrites the bait (hash + mtime change)
    victim.write_text("EXFILTRATED + tampered", encoding="utf-8")
    # advance the recorded mtime so the change is detectable regardless of clock
    new_mtime = T0 + 500
    import os
    os.utime(victim, (new_mtime, new_mtime))
    trips = canary.check(state, now=T0 + 600)
    tripped = [t for t in trips if Path(t["path"]) == victim]
    assert tripped and tripped[0]["tripped"] is True
    reasons = " ".join(tripped[0]["reasons"]).lower()
    assert "hash" in reasons


def test_check_reports_missing_canary(tmp_path):
    _res, state, ddir = _deploy(tmp_path, names=["crypto_wallet_seed.txt"])
    victim = next(ddir.glob("crypto_wallet_seed.txt"))
    victim.unlink()  # canary deleted/moved
    trips = canary.check(state, now=T0 + 100)
    tripped = [t for t in trips if Path(t["path"]) == victim]
    assert tripped and tripped[0]["tripped"] is True
    assert any("missing" in r.lower() for r in tripped[0]["reasons"])


def test_clear_removes_files_and_state(tmp_path):
    _res, state, ddir = _deploy(tmp_path)
    planted = list(ddir.glob("*"))
    assert planted, "nothing was planted"
    canary.clear(state)
    # all planted decoy files gone
    for p in planted:
        assert not p.exists(), f"decoy left behind: {p}"
    # state file gone too
    assert not state.exists()


def test_clear_is_safe_when_nothing_deployed(tmp_path):
    # clearing a non-existent state must not raise
    canary.clear(tmp_path / "does_not_exist.json")


def test_check_no_state_returns_empty(tmp_path):
    assert canary.check(tmp_path / "nope.json", now=T0) == []


def test_atime_alone_does_not_trip(tmp_path):
    # bump ONLY atime (a pure read on a last-access-enabled FS), leave content +
    # mtime as planted. atime is a weak/unreliable signal so it must NOT flip
    # tripped on its own -- otherwise check()'s own read would self-trip re-scans.
    _res, state, ddir = _deploy(tmp_path, names=["vpn_credentials.txt"])
    victim = next(ddir.glob("vpn_credentials.txt"))
    import os
    st = victim.stat()
    os.utime(victim, (st.st_atime + 9999, st.st_mtime))  # advance atime only
    trips = canary.check(state, now=T0 + 10000)
    rec = next(t for t in trips if Path(t["path"]) == victim)
    assert rec["tripped"] is False
    # but it IS noted as a weak hint
    assert any("atime" in r.lower() for r in rec["reasons"])


def test_check_is_idempotent_across_rescans(tmp_path):
    # running check() twice on untouched canaries must not self-trip on the
    # second run (check reads the file to hash it, which can bump atime).
    _res, state, _ddir = _deploy(tmp_path)
    canary.check(state, now=T0 + 60)
    second = canary.check(state, now=T0 + 120)
    assert all(t["tripped"] is False for t in second)
