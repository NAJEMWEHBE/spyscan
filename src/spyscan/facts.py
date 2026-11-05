# src/spyscan/facts.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict

def make_key(collector: str, *parts: str) -> str:
    """Deterministic, namespaced entity identity for baseline diffing.

    Contract (ADR 0002): parts are the entity's STABLE identity only -- fields
    that survive reboot, re-enumeration, and routine updates. Never a pid, port,
    timestamp, runtime state, or versioned path segment. Two scans with zero
    attacker/user action must yield the identical key set.
    """
    return collector + "::" + "::".join(p.strip() for p in parts)

# The attrs a collector may use for "the on-disk program this fact is about".
# Collectors spell it differently (processes: exe; autostarts: image_path;
# services/drivers: path), so EVERY reader goes through image_path_of -- two
# private copies of this list drifted apart once and no autostart was ever
# signature-checked (audit #2).
IMAGE_PATH_ATTRS = ("image_path", "exe", "image", "path")


def image_path_of(attrs: dict) -> str:
    """The fact's on-disk image path ('' if none), whichever attr holds it."""
    for key in IMAGE_PATH_ATTRS:
        val = str(attrs.get(key) or "").strip()
        if val:
            return val
    return ""


@dataclass(frozen=True)
class Fact:
    """One real-world persistence/activity entity, exactly one Fact per scan.

    ``attrs`` participate in diff equality (diff.py): every attr change must
    mean "someone did something". Volatile observations that can change with
    zero attacker/user action (pids, ephemeral ports, Running/Stopped state,
    counts, atime) go in ``observed`` -- persisted and usable by labels/scoring/
    reports, but invisible to the baseline diff. See docs/adr/0002.
    """
    collector: str
    entity_key: str
    kind: str
    label: str
    attrs: dict = field(default_factory=dict)
    attack_id: str | None = None
    observed: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Fact":
        return cls(
            collector=d["collector"], entity_key=d["entity_key"],
            kind=d["kind"], label=d["label"],
            attrs=dict(d.get("attrs", {})), attack_id=d.get("attack_id"),
            observed=dict(d.get("observed", {})),
        )

    def __eq__(self, other):  # frozen dataclass with dict field needs explicit eq
        return isinstance(other, Fact) and self.to_dict() == other.to_dict()

    def __hash__(self):
        return hash(self.entity_key)
