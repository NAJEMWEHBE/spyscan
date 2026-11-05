"""Audit #3: the local API must refuse anything that is not the spyscan window.

Before: any web page could POST /api/baseline (absorb an implant as trusted),
POST /api/canary/clear (disarm the decoys) or, via DNS rebinding, read
/api/status. A per-launch token (handed to the window in its URL, kept in a
SameSite=Strict cookie), a Host allowlist, an Origin check and a JSON-only POST
rule close all three. Tested once, through the Flask test client.
"""
from __future__ import annotations
import pytest

from spyscan.app import server

TOKEN = "t0k3n-for-tests"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(server.service, "run_baseline", lambda root, db: 1)
    monkeypatch.setattr(server.canary, "clear",
                        lambda state_path: {"removed": [], "missing": []})
    a = server.create_app(root=tmp_path, db=tmp_path / "b.db", token=TOKEN)
    a.config.update(TESTING=True)
    return a


def _authed(app):
    c = app.test_client()
    r = c.get("/?t=" + TOKEN)
    assert r.status_code in (302, 303)
    return c


def test_api_without_token_is_refused(app):
    c = app.test_client()
    assert c.get("/api/status").status_code == 403
    assert c.post("/api/baseline", json={}).status_code == 403
    assert c.post("/api/canary/clear", json={}).status_code == 403


def test_index_without_token_is_refused(app):
    assert app.test_client().get("/").status_code == 403


def test_wrong_token_is_refused(app):
    c = app.test_client()
    assert c.get("/?t=nope").status_code == 403
    assert c.get("/api/status", headers={"X-Spyscan-Token": "nope"}).status_code == 403


def test_handshake_sets_strict_cookie_and_strips_token_from_url(app):
    c = app.test_client()
    r = c.get("/?t=" + TOKEN)
    assert r.headers["Location"].endswith("/")
    assert "t=" not in r.headers["Location"]
    cookie = r.headers["Set-Cookie"]
    assert "SameSite=Strict" in cookie
    assert c.get("/").status_code == 200
    assert c.get("/api/status").status_code == 200


def test_token_header_works_for_the_launcher(app):
    r = app.test_client().get("/api/status", headers={"X-Spyscan-Token": TOKEN})
    assert r.status_code == 200


def test_cross_origin_post_is_refused_even_with_the_cookie(app):
    c = _authed(app)
    r = c.post("/api/baseline", json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = c.post("/api/canary/clear", json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_same_origin_post_is_allowed(app):
    c = _authed(app)
    r = c.post("/api/baseline", json={}, headers={"Origin": "http://localhost"})
    assert r.status_code == 200


def test_simple_request_content_type_is_refused(app):
    # text/plain is a CORS "simple request": no preflight, so it must be refused here
    c = _authed(app)
    r = c.post("/api/baseline", data="x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 415


def test_foreign_host_is_refused_even_with_the_token(app):
    # DNS rebinding: the page's own hostname resolves to 127.0.0.1
    r = app.test_client().get("/api/status", headers={
        "Host": "rebind.evil.example:51234", "X-Spyscan-Token": TOKEN})
    assert r.status_code == 403


@pytest.mark.parametrize("host", ["127.0.0.1:51234", "localhost:51234", "[::1]:51234"])
def test_loopback_hosts_are_accepted(app, host):
    r = app.test_client().get("/api/status", headers={"Host": host, "X-Spyscan-Token": TOKEN})
    assert r.status_code == 200


def test_report_link_accepts_the_token_query(app, tmp_path):
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "last_scan.html").write_text("<html>r</html>", encoding="utf-8")
    assert app.test_client().get("/api/report").status_code == 403
    assert app.test_client().get("/api/report?t=" + TOKEN).status_code == 200


def test_default_app_gets_a_random_token(tmp_path):
    a1 = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    a2 = server.create_app(root=tmp_path, db=tmp_path / "b.db")
    t1, t2 = a1.config["SPYSCAN_TOKEN"], a2.config["SPYSCAN_TOKEN"]
    assert t1 and t2 and t1 != t2 and len(t1) >= 32
    assert a1.test_client().get("/api/status").status_code == 403


def test_stale_cookie_from_an_earlier_launch_does_not_block_the_handshake(app):
    # cookies are not port-scoped: a previous launch's token cookie is still sent
    c = app.test_client()
    c.set_cookie(server.TOKEN_COOKIE, "old-launch-token", domain="localhost")
    assert c.get("/?t=" + TOKEN).status_code == 303
    assert c.get("/api/status").status_code == 200
