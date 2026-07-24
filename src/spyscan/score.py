# src/spyscan/score.py
from __future__ import annotations
from enum import StrEnum
from spyscan.facts import Fact


class Bucket(StrEnum):
    """The scoring verdict vocabulary AND its policy owner.

    A StrEnum, so it compares equal to and serializes as its plain string value
    ('ALERT'/'REVIEW'/'INFO') -- the JSON report + JS-UI contract is unchanged --
    while owning the actionability policy so no reader re-derives it.
    """
    ALERT = "ALERT"
    REVIEW = "REVIEW"
    INFO = "INFO"

    @property
    def is_actionable(self) -> bool:
        """Worth surfacing to the user (ALERT or REVIEW); INFO is collapsed.
        The single home of the 'which buckets do we show?' policy."""
        return self in (Bucket.ALERT, Bucket.REVIEW)

    @classmethod
    def for_score(cls, score: int) -> "Bucket":
        """Map a numeric score to its verdict bucket. The score->verdict
        thresholds live here, on the type that owns the vocabulary (not in a
        loose module function beside it)."""
        if score >= 8:
            return cls.ALERT
        if score >= 4:
            return cls.REVIEW
        return cls.INFO

# Remote endpoints that are inherently non-suspicious for a connection fact.
# A live scan yields hundreds of benign NEW localhost/ephemeral connections;
# without this floor every loopback socket would inflate the report.
_LOOPBACK_V4_PREFIX = "127."          # 127.0.0.0/8
_LINK_LOCAL_V4_PREFIX = "169.254."    # 169.254.0.0/16
_LOOPBACK_V6 = {"::1", "0:0:0:0:0:0:0:1"}


def _is_benign_remote(remote_ip: str | None) -> bool:
    """True if a connection's remote endpoint is loopback / link-local / empty."""
    ip = (remote_ip or "").strip().lower()
    if not ip:
        return True
    if ip in _LOOPBACK_V6:
        return True
    if ip.startswith(_LOOPBACK_V4_PREFIX) or ip.startswith(_LINK_LOCAL_V4_PREFIX):
        return True
    return False


def no_resolvable_parent(f: Fact) -> bool:
    """True when a process entity has no resolvable parent at all.

    Folded process facts carry observed['parents'] (ADR 0002: volatile, not
    diffed); every instance unresolvable = the signal. Falls back to the legacy
    single-instance attrs['parent'] shape for hand-built/old facts.
    """
    parents = f.observed.get("parents")
    if parents:
        return all(p == "" for p in parents)
    return f.attrs.get("parent") == ""


def score_fact(f: Fact) -> dict:
    a = f.attrs
    score = 0
    reasons: list[str] = []

    def add(pts, why):
        nonlocal score
        score += pts
        reasons.append(f"+{pts} {why}")

    # known-bad signals: if ANY of these fire, the entity is suspicious no matter
    # who signed it (stolen-cert / LOLBin / signed implant), so the known-good
    # allowlist floor below MUST NOT apply -- we score normally instead.
    # A tripped canary is known-bad-class too: a decoy the user never created was
    # read/modified, so the allowlist floor must NEVER silence it.
    known_bad = bool(a.get("defender_hit")
                     or a.get("ioc_procname_hit") or a.get("canary_tripped"))

    # known-good floor: a fact the allowlist matched (incl. the built-in verified Microsoft-
    # signed rule, folded here from score.py -- see ADR 0001 / allowlist.py) floors to INFO, but
    # ONLY when no known-bad signal is present, so it can never hide real malware. The pipeline
    # sets attrs['allowlisted'] + allowlist_reason.
    if not known_bad and a.get("allowlisted"):
        return {"score": 0, "bucket": Bucket.INFO,
                "reasons": [a.get("allowlist_reason", "allowlisted")]}

    # loopback/ephemeral netconn churn: a connection to loopback/link-local/empty
    # remote is benign no matter how new it is (NOT applied to listening sockets'
    # remote being empty? empty remote == not reaching out, so still benign).
    if f.kind == "connection" and _is_benign_remote(a.get("remote_ip")):
        return {"score": 0, "bucket": Bucket.INFO,
                "reasons": ["benign: loopback/link-local/no remote endpoint"]}

    if a.get("is_new"):
        add(3, "new since baseline")
    if a.get("signed") is False or a.get("verified") is False:
        add(2, "unsigned / unverified binary")
    if a.get("from_temp"):
        # +3 (not the plan's +2): execution from %TEMP%/AppData is a strong,
        # well-cited signal (GROUNDING-BRIEF s2) and the plan's own Task-12 test
        # requires temp+unsigned+new to reach ALERT (>=8). 3+2+3 = 8.
        add(3, "runs from temp/appdata")
    if f.kind == "process" and no_resolvable_parent(f):
        add(2, "no resolvable parent")
    if a.get("ioc_domain_hit"):
        add(3, "connects to known mercenary/C2 domain")
    if a.get("ioc_procname_hit"):
        add(5, "process name matches known implant daemon")
    if a.get("in_use_now") and not a.get("trusted_ms"):
        add(3, "webcam/mic in use by non-allowlisted app")
    if a.get("defender_hit"):
        add(5, "Microsoft Defender flagged this file")
    if a.get("canary_tripped"):
        # a honeyfile decoy was read/modified/deleted -- a high-confidence
        # behavioral spying signal that stands on its own (-> ALERT at +8) and is
        # routed through known_bad above so the allowlist/MS floor can never silence it.
        add(8, "canary tripwire fired (decoy file accessed/modified)")
    if a.get("hidden_flag"):
        add(1, "hidden-window flag")
    if a.get("removed_since_baseline"):
        add(3, "removed since baseline (persistence entry gone -- benign uninstall or possible implant cleanup)")
    # observed-delta signals (set by pipeline.observed_deltas): weak evidence on
    # their own (+1 -> INFO alone), they only surface combined with real signals.
    if a.get("instances_grew"):
        add(1, f"instance count grew {a['instances_grew']} since baseline "
               "(was single-instance -- possible masqueraded twin)")
    if a.get("driver_started"):
        add(1, "driver started since baseline (was stopped -- dormant driver activated)")

    return {"score": score, "bucket": Bucket.for_score(score), "reasons": reasons}
