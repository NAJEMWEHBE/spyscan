# src/spyscan/service.py
"""Reusable scan service shared by the CLI and the desktop app (DRY).

This wraps the existing engine (collectors -> pipeline.build_findings ->
report renderers) behind two plain functions so both the `spyscan` CLI and the
`spyscan-app` GUI drive identical detection logic. NOTHING here re-implements
detection; it only orchestrates the pieces that cli.py already wired together.

Paths (DB, indicators, allowlist, runs/) are all resolved from a `root`
argument so tests can repoint them via tmp_path, exactly like the CLI tests do.
"""
from __future__ import annotations
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from spyscan.store import BaselineStore
from spyscan.collectors import COLLECTORS
from spyscan.collectors.base import ScanContext
from spyscan.pipeline import build_findings
from spyscan.enrich import defender as _defender
from spyscan.finding import Finding
from spyscan.score import Bucket
from spyscan.rules.ioc import IOCMatcher
from spyscan.allowlist import Allowlist
from spyscan.report.json_out import render_json
from spyscan.report.html import render_html
from spyscan.resources import resource_dir, bundle_dir, app_base, is_frozen
from spyscan import canary

# Writable runtime base: dev -> repo root; frozen -> the dir next to the exe.
# baseline.db + runs/ live here so a one-file build's throwaway _MEIPASS is never
# used for state. ``service.ROOT`` is THE single seam: monkeypatch it and every
# resolver below repoints, because each reads it at CALL TIME via ``_root``.
# baseline.db is derived from the resolved root (``<root>/baseline.db``) inside
# run_baseline/run_scan, so there is no separate DB seam to keep in sync.
ROOT = app_base()


def _root(root: Path | None) -> Path:
    """Resolve a path root: an explicit value wins; ``None`` falls back to the
    live module ``ROOT`` read AT CALL TIME (so a test that monkeypatches
    ``service.ROOT`` takes effect even for callers that pass nothing)."""
    return Path(root) if root is not None else ROOT


def indicators_dir(root: Path | None = None) -> Path:
    """IOC indicator-list dir.

    Frozen: resolve the BUNDLED copy (read-only, under the package in _MEIPASS).
    Dev: the in-tree ``<root>/src/spyscan/rules/indicators`` so tests that repoint
    ``root`` (and the real source tree) keep working.
    """
    if is_frozen():
        return resource_dir("rules", "indicators")
    return _root(root) / "src" / "spyscan" / "rules" / "indicators"


def allowlist_path(root: Path | None = None) -> Path:
    """Active allowlist config file.

    Frozen: prefer a user-editable copy next to the exe (``<exe>/config``) if it
    exists, else the bundled default; this lets a user tune the allowlist without
    re-freezing. Dev: the in-tree ``<root>/config/allowlist.json``.
    """
    if is_frozen():
        external = app_base() / "config" / "allowlist.json"
        return external if external.exists() else bundle_dir("config", "allowlist.json")
    return _root(root) / "config" / "allowlist.json"


def runs_dir(root: Path | None = None) -> Path:
    """Per-run report output dir resolved against a given root."""
    return _root(root) / "runs"


def canary_state_path(root: Path | None = None) -> Path:
    """Canary honeyfile state file, resolved against ``root``.

    Delegates to ``canary.default_state_path`` -- the ONE place the
    ``config/canary_state.json`` join is spelled -- so every surface and the
    canary module itself agree on the location.

    The scan-time canary *collector* also resolves through the same join: it
    cannot import ``service`` (that is a cycle -- service imports the collectors),
    so instead of asking here it reads ``canary.default_state_path(ctx.root)``,
    where ``ctx.root`` is the scan root the service threaded in via ScanContext.
    Both therefore resolve against the same root -- the surface path and the
    scan-time read stay in lock-step. See ``tests/test_canary_collector.py``
    (``test_scantime_collector_honors_ctx_root``).
    """
    return canary.default_state_path(_root(root))


def collect_all(ctx: ScanContext, log=print) -> list:
    """Run every collector; a single failing collector must not kill the scan.

    Kept here (not just in cli) so the app and any future caller share the same
    fault-tolerant collection. The CLI keeps its own thin wrapper that delegates
    here, so the existing `cli._collect_all` monkeypatch in tests still works.

    ``ctx`` is threaded into each collector so config-needing collectors (canary)
    resolve their paths from the scan root without importing service.
    """
    facts = []
    for c in COLLECTORS:
        try:
            facts += c.collect(ctx)
        except Exception as e:  # one collector failing must not kill the scan
            log(f"  [warn] collector {c.name} failed: {e}")
    return facts


def run_baseline(root: Path | None = None, db: Path | None = None, *,
                 collect=None, log=print) -> int:
    """Capture a trusted-machine baseline. Returns the saved fact count."""
    root = _root(root)
    db = Path(db) if db is not None else root / "baseline.db"
    store = BaselineStore(db)
    ctx = ScanContext(root=root, now=time.time())
    facts = collect(ctx) if collect is not None else collect_all(ctx, log=log)
    store.save_baseline(facts)
    log(f"baseline saved: {len(facts)} facts -> {db}")
    return len(facts)


def _summary(findings: list[Finding]) -> dict:
    """Bucket counts + allowlisted + total for the UI/headers."""
    alert = sum(1 for f in findings if f.bucket == Bucket.ALERT)
    review = sum(1 for f in findings if f.bucket == Bucket.REVIEW)
    info = sum(1 for f in findings if f.bucket == Bucket.INFO)
    allowlisted = sum(1 for f in findings if f.fact.attrs.get("allowlisted"))
    return {"alert": alert, "review": review, "info": info,
            "allowlisted": allowlisted, "total": len(findings)}


def run_scan(root: Path | None = None, db: Path | None = None, *,
             collect=None, log=print, enable_defender: bool = False,
             ind: Path | None = None, allowlist_file: Path | None = None) -> dict:
    """Run a full scan: collect -> load IOC + allowlist -> build_findings ->
    write both report files -> return a structured dict.

    Returns:
      {
        "meta": {"host", "when"},
        "summary": {"alert","review","info","allowlisted","total"},
        "findings": [...ALL findings, every bucket...],
        "report_html_path": str,
        "report_json_path": str,
      }

    `ind` / `allowlist_file` optionally override the root-derived defaults; the
    CLI and app pass neither and let service resolve them from `root` (service is
    the single owner of path/config resolution). The service-level tests still use
    these overrides to point at a tmp indicators/allowlist dir.

    `enable_defender` opts into the heavy per-file Windows Defender second-opinion
    scan (off by default); build_findings caps how many files it actually scans.

    A missing baseline raises RuntimeError so callers (CLI/app) can report it
    explicitly. Detection itself is delegated to build_findings.
    """
    root = _root(root)
    db = Path(db) if db is not None else root / "baseline.db"
    store = BaselineStore(db)
    base = store.load_baseline()
    if not base:
        raise RuntimeError("no baseline yet - run a baseline first")

    ctx = ScanContext(root=root, now=time.time())
    current = collect(ctx) if collect is not None else collect_all(ctx, log=log)
    ioc = IOCMatcher.from_dir(ind if ind is not None else indicators_dir(root))
    # Load the user allowlist (known-good software); known-bad always overrides
    # it in score_fact, so it can never hide real malware.
    allowlist = Allowlist.load(
        allowlist_file if allowlist_file is not None else allowlist_path(root))
    # Defender is a heavy, opt-in per-file second opinion (off by default). When
    # enabled, pass its on-demand single-file scanner; build_findings caps how many
    # of the most-suspicious files it actually scans (defender_max).
    findings = build_findings(base, current, ioc, max_enrich=50,
                              defender=_defender.scan_file if enable_defender else None,
                              allowlist=allowlist, log=log)

    meta = {"host": socket.gethostname(),
            "when": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    runs = runs_dir(root)
    runs.mkdir(exist_ok=True)
    html_path = runs / "last_scan.html"
    json_path = runs / "last_scan.json"
    json_path.write_text(render_json(findings, meta), encoding="utf-8")
    html_path.write_text(render_html(findings, meta), encoding="utf-8")

    return {
        "meta": meta,
        "summary": _summary(findings),
        "findings": findings,
        "report_html_path": str(html_path),
        "report_json_path": str(json_path),
    }
