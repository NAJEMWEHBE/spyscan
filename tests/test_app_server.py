# tests/test_app_server.py
import json
from pathlib import Path

import pytest

from spyscan.app import server
from spyscan.facts import Fact
from spyscan.finding import Finding


def _fake_finding(bucket, score, label):
    return Finding(fact=Fact("processes", f"processes::{label}::{label}",
                             "process", label, {}),
                   score=score, bucket=bucket, reasons=["why"], attack_id=None)


@pytest.fixture
def client(tmp_path):
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    app.config.update(TESTING=True)
    return app.test_client()


def test_index_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"spyscan" in r.data
    assert b"<!doctype html" in r.data.lower() or b"<!DOCTYPE html" in r.data


def test_status_shape_no_baseline(client, tmp_path):
    r = client.get("/api/status")
    assert r.status_code == 200
    d = r.get_json()
    assert set(d) == {"baseline_exists", "baseline_count", "last_scan", "allowlist"}
    assert d["baseline_exists"] is False
    assert d["baseline_count"] is None
    assert d["last_scan"] is None
    assert "path" in d["allowlist"] and "counts" in d["allowlist"]


def test_status_reports_baseline(tmp_path, monkeypatch):
    monkeypatch.setattr(server.service, "run_baseline",
                        lambda root, db: 3)
    # seed a real baseline so _baseline_count reads it
    from spyscan.store import BaselineStore
    BaselineStore(tmp_path / "b.db").save_baseline(
        [Fact("processes", f"processes::{i}::{i}", "process", str(i), {})
         for i in range(3)])
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    c = app.test_client()
    d = c.get("/api/status").get_json()
    assert d["baseline_exists"] is True
    assert d["baseline_count"] == 3


def test_baseline_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(server.service, "run_baseline",
                        lambda root, db: 7)
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    r = app.test_client().post("/api/baseline")
    assert r.status_code == 200
    assert r.get_json() == {"ok": True, "count": 7}


def test_scan_returns_summary_and_only_alert_review(tmp_path, monkeypatch):
    # service returns full findings (ALERT+REVIEW+INFO); endpoint must trim INFO
    full = [
        _fake_finding("ALERT", 5, "bad"),
        _fake_finding("REVIEW", 2, "meh"),
        _fake_finding("INFO", 0, "fine1"),
        _fake_finding("INFO", 0, "fine2"),
    ]
    fake_result = {
        "meta": {"host": "h", "when": "now"},
        "summary": {"alert": 1, "review": 1, "info": 2, "allowlisted": 0, "total": 4},
        "findings": full,
        "report_html_path": "x/last_scan.html",
        "report_json_path": "x/last_scan.json",
    }
    monkeypatch.setattr(server.service, "run_scan",
                        lambda root, db, **k: fake_result)
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    r = app.test_client().post("/api/scan")
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    # full summary carried through
    assert d["summary"] == {"alert": 1, "review": 1, "info": 2,
                            "allowlisted": 0, "total": 4}
    # findings trimmed to ALERT + REVIEW only
    buckets = sorted(f["bucket"] for f in d["findings"])
    assert buckets == ["ALERT", "REVIEW"]
    assert len(d["findings"]) == 2


def test_scan_without_baseline_returns_409(tmp_path, monkeypatch):
    def boom(root, db, **k):
        raise RuntimeError("no baseline yet")
    monkeypatch.setattr(server.service, "run_scan", boom)
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    r = app.test_client().post("/api/scan")
    assert r.status_code == 409
    assert r.get_json()["ok"] is False


def test_scan_defender_query_param_threads_enable_defender(tmp_path, monkeypatch):
    # POST /api/scan?defender=1 -> run_scan(enable_defender=True); bare POST -> False.
    captured = {}

    def fake(root, db, **k):
        captured.clear(); captured.update(k)
        return {"meta": {}, "findings": [],
                "summary": {"alert": 0, "review": 0, "info": 0,
                            "allowlisted": 0, "total": 0},
                "report_html_path": "x", "report_json_path": "y"}
    monkeypatch.setattr(server.service, "run_scan", fake)
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")

    app.test_client().post("/api/scan?defender=1")
    assert captured.get("enable_defender") is True

    app.test_client().post("/api/scan")
    assert captured.get("enable_defender") is False


def test_report_404_before_scan(client):
    assert client.get("/api/report").status_code == 404


def test_report_served_after_scan(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "last_scan.html").write_text("<h1>spyscan report</h1>", encoding="utf-8")
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    r = app.test_client().get("/api/report")
    assert r.status_code == 200
    assert b"spyscan report" in r.data


def test_allowlist_endpoint(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allowlist.json").write_text(
        json.dumps({"path_globs": ["a", "b"], "signers": ["x"]}), encoding="utf-8")
    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    d = app.test_client().get("/api/allowlist").get_json()
    assert d["counts"]["path_globs"] == 2
    assert d["counts"]["signers"] == 1
    # ADR 0001: the built-in verified Microsoft-signed floor is surfaced too
    assert any("microsoft" in b.lower() for b in d["builtins"])


# --- UNIT 4: canary tripwire API routes ---

def test_canary_status_no_deploy(client):
    d = client.get("/api/canary/status").get_json()
    assert d["deployed"] is False
    assert d["canaries"] == []
    assert d["tripped"] == 0


def test_canary_deploy_status_clear_roundtrip(tmp_path, monkeypatch):
    # patch the server's canary module to plant into an isolated tmp dir so the
    # route exercises real deploy/check/clear without touching real Desktop.
    from spyscan import canary as canary_mod
    into = tmp_path / "decoys"
    real_deploy = canary_mod.deploy

    def deploy_into(targets=None, state_path=None, now=0.0, names=None):
        return real_deploy(targets=[into], state_path=state_path, now=now, names=names)
    monkeypatch.setattr(server.canary, "deploy", deploy_into)

    app = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    c = app.test_client()

    # deploy
    r = c.post("/api/canary/deploy")
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True and d["planted"] >= 1
    state = tmp_path / "config" / "canary_state.json"
    assert state.exists()

    # status: deployed, none tripped
    d = c.get("/api/canary/status").get_json()
    assert d["deployed"] is True
    assert d["tripped"] == 0
    assert len(d["canaries"]) >= 1

    # trip one
    import json as _json, os
    data = _json.loads(state.read_text(encoding="utf-8"))
    victim = Path(data["canaries"][0]["path"])
    victim.write_text("STOLEN", encoding="utf-8")
    os.utime(victim, (data["deployed_at"] + 999, data["deployed_at"] + 999))

    d = c.get("/api/canary/status").get_json()
    assert d["tripped"] >= 1
    assert any(cn["tripped"] for cn in d["canaries"])

    # clear: files + state gone
    r = c.post("/api/canary/clear")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    assert not state.exists()
    assert not victim.exists()
