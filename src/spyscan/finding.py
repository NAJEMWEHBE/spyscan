# src/spyscan/finding.py
from __future__ import annotations
from dataclasses import dataclass, field
from spyscan.facts import Fact
from spyscan.score import Bucket


@dataclass
class Finding:
    """A scored Fact -- the owned record of the detection pipeline.

    Replaces the old ``{"fact": <dict>, "score", "bucket", "reasons",
    "attack_id"}`` finding dict. The Fact stays LIVE through the whole pipeline
    (never round-tripped Fact -> dict -> Fact); enrichment mutates
    ``fact.attrs`` in place and re-scores. Delegates the actionability policy to
    :class:`~spyscan.score.Bucket` (its true owner) and owns its own JSON
    serialization (:meth:`to_dict` / :meth:`from_dict`), so no reader re-derives
    either.
    """
    fact: Fact
    score: int
    bucket: Bucket
    reasons: list[str] = field(default_factory=list)
    attack_id: str | None = None

    def __post_init__(self):
        # Enforce the field's type invariant: bucket is always a Bucket, even if
        # constructed from a plain string (from_dict, tests). An unknown value
        # raises ValueError here -- loudly, at construction.
        if not isinstance(self.bucket, Bucket):
            self.bucket = Bucket(self.bucket)

    def is_actionable(self) -> bool:
        """True iff worth surfacing to the user (ALERT or REVIEW). INFO is
        collapsed. Delegates to the policy's owner, :class:`Bucket` -- readers
        ask this, they never re-derive ``bucket in (...)`` themselves."""
        return self.bucket.is_actionable

    def to_dict(self) -> dict:
        """JSON-serializable form for the report/audit trail. ``bucket`` is
        emitted as its plain string value (the JSON report + JS-UI contract).
        Exact inverse of :meth:`from_dict` (guarded by a round-trip property test)."""
        return {
            "fact": self.fact.to_dict(),
            "score": self.score,
            "bucket": str(self.bucket),
            "reasons": list(self.reasons),
            "attack_id": self.attack_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Rebuild a Finding from :meth:`to_dict` output (``bucket`` is coerced
        back to :class:`Bucket` in ``__post_init__``). Owning both build and
        parse here is the structural anti-drift guard for the serialized shape."""
        return cls(
            fact=Fact.from_dict(d["fact"]),
            score=d["score"],
            bucket=d["bucket"],
            reasons=list(d.get("reasons", [])),
            attack_id=d.get("attack_id"),
        )
