from __future__ import annotations
from spyscan.facts import Fact, make_key
from spyscan import canary as _canary
from spyscan import canary_audit as _audit
from spyscan.collectors.base import Collector, ScanContext

name = "canary"

# T1530 = Data from Local System: an implant reading local files it shouldn't.
# A tripped honeyfile is exactly that behavior, so we tag canary trips with it.
_ATTACK = "T1530"


def gather(state_path=None, now: float | None = None) -> list[dict]:
    """Load canary_state.json (if absent -> []) and run canary.check + a
    best-effort access audit on tripped canaries.

    Pure-ish: state_path/now are injectable for tests. If no canaries were ever
    deployed there is no state file, so this returns [] and the scan gains zero
    noise. ``now`` defaults to wall-clock only in production (the live scan).
    """
    import time
    if now is None:
        now = time.time()
    trips = _canary.check(state_path, now=now)
    if not trips:
        return []

    tripped = [t for t in trips if t.get("tripped")]
    # best-effort attribution: WHO touched the tripped decoys (4663). Returns []
    # without admin/SACL; never raises. Keyed by accessed object path.
    audit_by_path: dict[str, list[dict]] = {}
    if tripped:
        try:
            events = _audit.gather(paths=[t["path"] for t in tripped], since=None)
        except Exception:
            events = []
        for ev in events:
            # regroup case-insensitively: canary_audit's parser deliberately
            # matches ObjectName case-insensitively (canary_audit.py), so the
            # regroup here must too, or a casing mismatch silently drops the
            # who-touched-it attribution.
            audit_by_path.setdefault(
                (ev.get("object_name") or "").strip().lower(), []).append(ev)

    rows = []
    for t in trips:
        ev = audit_by_path.get((t.get("path") or "").strip().lower(), [])
        rows.append({**t, "audit": ev})
    return rows


def parse(rows: list[dict]) -> list[Fact]:
    """Emit a Fact(kind='canary_trip', ...) ONLY for tripped canaries.

    Untouched canaries produce no fact (zero noise). Each fact carries
    canary_tripped=True so score_fact treats it as a known-bad-class ALERT that
    the allowlist cannot silence, plus the human-readable reasons + any process
    attribution from the access audit.
    """
    facts = []
    for r in rows:
        if not r.get("tripped"):
            continue
        path = r.get("path", "")
        fname = path.replace("\\", "/").rsplit("/", 1)[-1] or path
        reasons = r.get("reasons", [])
        audit = r.get("audit", []) or []
        culprits = sorted({e.get("process_name", "") for e in audit
                           if e.get("process_name")})
        # Volatile evidence out of the diffed attrs (ADR 0002 rule 3): the atime
        # hint and the rolling-window audit attribution can change with no new
        # snoop action, and a tripped canary must SETTLE once the user
        # re-baselines instead of re-flagging 'changed' forever. Reliable tamper
        # evidence (hash/mtime/size/missing) stays diffed.
        evidence = dict(r.get("evidence", {}))
        observed = {}
        if "atime" in evidence:
            observed["atime"] = evidence.pop("atime")
        stable_reasons = [x for x in reasons if not x.startswith("atime advanced")]
        weak = [x for x in reasons if x.startswith("atime advanced")]
        if weak:
            observed["atime_hint"] = weak
        attrs = {
            "canary_tripped": True,
            "path": path,
            "reasons": stable_reasons,
            "evidence": evidence,
        }
        if culprits:
            observed["accessed_by"] = culprits
        label = f"canary tripped: {fname}"
        if culprits:
            label += " (accessed by " + ", ".join(culprits) + ")"
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, path),
            kind="canary_trip",
            label=label,
            attack_id=_ATTACK,
            attrs=attrs,
            observed=observed,
        ))
    return facts


class CanaryCollector(Collector):
    """Honeyfile tripwire wired as a collector -- the ONE collector that consumes
    ctx. It resolves its state file from ``ctx.root`` (via canary.default_state_path)
    and uses the scan-wide ``ctx.now``, so a repointed scan root now drives the
    scan-time canary read (this is what closes candidate #01's deferred gap: the
    surface path and the scan-time read finally resolve through the same root)."""
    name = "canary"

    def gather(self, ctx: ScanContext) -> list[dict]:
        state_path = _canary.default_state_path(ctx.root)
        return gather(state_path=state_path, now=ctx.now)

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
