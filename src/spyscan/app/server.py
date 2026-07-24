# src/spyscan/app/server.py
"""Localhost-only HTTP API for the spyscan desktop app.

A thin Flask layer over spyscan.service -- it does NO detection itself, it only
exposes the reusable service (collect -> build_findings -> report) to the local
UI. Bind it to 127.0.0.1 only (the launcher does this); there is no auth because
it is single-user loopback, never a network service.
"""
from __future__ import annotations
import json
from pathlib import Path

from flask import Flask, jsonify, send_from_directory, abort, request

from spyscan import service
from spyscan import canary
from spyscan.store import BaselineStore
from spyscan.allowlist import Allowlist
from spyscan.resources import resource_dir

# Frozen-aware: dev -> src/spyscan/app/ui; PyInstaller -> <_MEIPASS>/spyscan/app/ui.
_UI_DIR = resource_dir("app", "ui")


def _baseline_count(db: Path) -> int | None:
    """Return the number of baseline facts, or None if no baseline exists yet."""
    try:
        facts = BaselineStore(db).load_baseline()
    except Exception:
        return None
    return len(facts) if facts else None


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


def create_app(root: Path | None = None, db: Path | None = None) -> Flask:
    """App factory. `root`/`db` default to the service's repo-rooted paths so the
    app scans the same surface the CLI does; tests pass tmp paths."""
    root = Path(root) if root is not None else service.ROOT
    db = Path(db) if db is not None else root / "baseline.db"

    app = Flask(__name__, static_folder=None)
    app.config["SPYSCAN_ROOT"] = root
    app.config["SPYSCAN_DB"] = db

    @app.get("/")
    def index():
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
        trips = canary.check(service.canary_state_path(root), now=time.time())
        deployed = bool(trips)
        tripped = sum(1 for t in trips if t["tripped"])
        canaries = [{"path": t["path"], "tripped": t["tripped"],
                     "reasons": t["reasons"]} for t in trips]
        return jsonify({"deployed": deployed, "tripped": tripped,
                        "canaries": canaries})

    @app.post("/api/canary/clear")
    def api_canary_clear():
        res = canary.clear(service.canary_state_path(root))
        return jsonify({"ok": True, "removed": res["removed"],
                        "missing": res["missing"]})

    return app
