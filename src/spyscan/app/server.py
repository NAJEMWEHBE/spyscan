# src/spyscan/app/server.py
"""Localhost-only HTTP API for the spyscan desktop app.

A thin Flask layer over spyscan.service -- it does NO detection itself, it only
exposes the reusable service (collect -> build_findings -> report) to the local
UI. Bind it to 127.0.0.1 only (the launcher does this).

Loopback is NOT a trust boundary: any web page the user visits can send requests
to 127.0.0.1, and DNS rebinding lets it read the answers. So one ``before_request``
guard (``_guard``) refuses every request that is not from the spyscan window:

* Host must be a loopback name (127.0.0.1 / localhost / [::1]) -- kills rebinding.
* Every route except /ui/* static assets needs the per-launch token: the launcher
  opens ``/?t=<token>``; that sets a SameSite=Strict cookie and redirects to ``/``.
  The launcher itself may send ``X-Spyscan-Token``; the report link may carry ``?t=``.
* A request carrying an Origin must come from the same origin.
* POSTs must be ``application/json`` (a CORS "simple request" can't send that
  without a preflight, which this server never approves).
"""
from __future__ import annotations
import hmac
import json
import secrets
from pathlib import Path

from flask import Flask, jsonify, send_from_directory, abort, request, redirect

from spyscan import service
from spyscan import canary
from spyscan.store import baseline_count
from spyscan.allowlist import Allowlist
from spyscan.resources import resource_dir

# Frozen-aware: dev -> src/spyscan/app/ui; PyInstaller -> <_MEIPASS>/spyscan/app/ui.
_UI_DIR = resource_dir("app", "ui")

TOKEN_COOKIE = "spyscan_token"
TOKEN_HEADER = "X-Spyscan-Token"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})


def _hostname(host: str) -> str:
    """'127.0.0.1:5000' -> '127.0.0.1'; '[::1]:5000' -> '[::1]'."""
    host = (host or "").strip().lower()
    if host.startswith("["):
        return host[:host.find("]") + 1] if "]" in host else host
    return host.rsplit(":", 1)[0] if ":" in host else host


def _same(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


def _baseline_count(db: Path) -> int | None:
    """Return the number of baseline facts, or None if no baseline exists yet.
    Read-only: a status read never creates baseline.db (audit #17)."""
    return baseline_count(db)


def _last_scan_meta(root: Path) -> dict | None:
    """meta block of the most recent scan, read back from runs/last_scan.json."""
    p = service.runs_dir(root) / "last_scan.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data.get("meta")


def _allowlist_info(root: Path) -> dict:
    """Allowlist file path + per-rule counts for the UI note."""
    path = service.allowlist_path(root)
    al = Allowlist.load(path)
    return {"path": str(path),
            "exists": path.exists(),
            "builtins": al.builtin_rules(),
            "counts": {"path_globs": len(al.path_globs),
                       "signers": len(al.signers),
                       "sha256": len(al.sha256),
                       "entity_keys": len(al.entity_keys)}}


def create_app(root: Path | None = None, db: Path | None = None,
               token: str | None = None) -> Flask:
    """App factory. `root`/`db` default to the service's repo-rooted paths so the
    app scans the same surface the CLI does; tests pass tmp paths. `token` is the
    per-launch secret every request must prove (a fresh random one by default;
    read it back from ``app.config["SPYSCAN_TOKEN"]``)."""
    root = Path(root) if root is not None else service.ROOT
    db = Path(db) if db is not None else root / "baseline.db"
    token = token or secrets.token_urlsafe(32)

    app = Flask(__name__, static_folder=None)
    app.config["SPYSCAN_ROOT"] = root
    app.config["SPYSCAN_DB"] = db
    app.config["SPYSCAN_TOKEN"] = token

    @app.before_request
    def _guard():
        if _hostname(request.host) not in _LOOPBACK_HOSTS:
            abort(403, "spyscan only answers on a loopback host name")
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/").lower() != request.host_url.rstrip("/").lower():
            abort(403, "cross-origin request refused")
        if request.path.startswith("/ui/"):
            return None  # public static assets (css/js), no data
        # any one valid proof is enough (a stale cookie from an earlier launch
        # must not shadow a fresh ?t= handshake: cookies are not port-scoped)
        presented = (request.cookies.get(TOKEN_COOKIE), request.headers.get(TOKEN_HEADER),
                     request.args.get("t"))
        if not any(_same(p or "", token) for p in presented):
            abort(403, "missing or wrong spyscan session token")
        if request.method == "POST" and not request.is_json:
            abort(415, "POST bodies must be application/json")
        return None

    @app.get("/")
    def index():
        if request.args.get("t"):
            # handshake: keep the token in a cookie, drop it from the URL/history
            resp = redirect("/", code=303)
            resp.set_cookie(TOKEN_COOKIE, token, samesite="Strict", path="/")
            return resp
        return send_from_directory(_UI_DIR, "index.html")

    @app.get("/ui/<path:fname>")
    def ui_static(fname):
        # serve app/ui/*.css/.js (no traversal: send_from_directory is safe)
        return send_from_directory(_UI_DIR, fname)

    @app.get("/api/status")
    def api_status():
        count = _baseline_count(db)
        return jsonify({
            "baseline_exists": count is not None,
            "baseline_count": count,
            "last_scan": _last_scan_meta(root),
            "allowlist": _allowlist_info(root),
        })

    @app.post("/api/baseline")
    def api_baseline():
        n = service.run_baseline(root, db)
        return jsonify({"ok": True, "count": n})

    @app.post("/api/scan")
    def api_scan():
        # opt-in Windows Defender deep scan (?defender=1); off unless requested.
        enable_defender = (request.args.get("defender") or "").lower() in ("1", "true", "on")
        try:
            result = service.run_scan(root, db, enable_defender=enable_defender)
        except RuntimeError as e:
            return jsonify({"ok": False, "error": str(e)}), 409
        # Trim findings to the actionable set (ALERT + REVIEW) -- the UI does not
        # need the thousands of benign INFO facts. summary carries full counts.
        shown = [f for f in result["findings"] if f.is_actionable()]
        return jsonify({
            "ok": True,
            "meta": result["meta"],
            "summary": result["summary"],
            "findings": [f.to_dict() for f in shown],
            "report_html_path": result["report_html_path"],
            "report_json_path": result["report_json_path"],
        })

    @app.get("/api/report")
    def api_report():
        # serve the latest raw HTML report
        p = service.runs_dir(root) / "last_scan.html"
        if not p.exists():
            abort(404, "no scan report yet - run a scan first")
        return send_from_directory(p.parent, p.name)

    @app.get("/api/allowlist")
    def api_allowlist():
        return jsonify(_allowlist_info(root))

    # --- canary tripwire (local honeyfile) routes ---

    @app.post("/api/canary/deploy")
    def api_canary_deploy():
        import time
        res = canary.deploy(state_path=service.canary_state_path(root), now=time.time())
        return jsonify({"ok": True, "planted": res["planted"],
                        "canaries": res["canaries"], "skipped": res["skipped"]})

    @app.get("/api/canary/status")
    def api_canary_status():
        import time
        from spyscan.collectors import canary as canary_collector
        # same rows as the scan: a decoy that was only READ shows as tripped too
        trips = canary_collector.gather(service.canary_state_path(root), now=time.time())
        deployed = bool(trips)
        tripped = sum(1 for t in trips if t["tripped"])
        canaries = [{"path": t["path"], "tripped": t["tripped"],
                     "reasons": t["reasons"],
                     "accessed_by": sorted({e.get("process_name", "")
                                            for e in t.get("audit", [])
                                            if e.get("process_name")})}
                    for t in trips]
        return jsonify({"deployed": deployed, "tripped": tripped,
                        "canaries": canaries})

    @app.get("/api/canary/audit-setup")
    def api_canary_audit_setup():
        # the elevated commands that let a scan see a decoy being READ (#9).
        # Text only: nothing is run or elevated from here.
        from spyscan import canary_audit
        paths = canary.tracked_paths(service.canary_state_path(root))
        return jsonify({"deployed": bool(paths),
                        "commands": canary_audit.enable_audit_commands(paths) if paths else ""})

    @app.post("/api/canary/clear")
    def api_canary_clear():
        res = canary.clear(service.canary_state_path(root))
        return jsonify({"ok": True, "removed": res["removed"],
                        "missing": res["missing"]})

    return app
