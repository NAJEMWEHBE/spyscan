# src/spyscan/diff.py
from __future__ import annotations
from spyscan.facts import Fact

def diff_facts(baseline: list[Fact], current: list[Fact]) -> dict[str, list[Fact]]:
    """Compare by entity_key. 'changed' = same key, different attrs."""
    base = {f.entity_key: f for f in baseline}
    curr = {f.entity_key: f for f in current}
    added   = [curr[k] for k in curr.keys() - base.keys()]
    removed = [base[k] for k in base.keys() - curr.keys()]
    changed = [curr[k] for k in base.keys() & curr.keys()
               if curr[k].attrs != base[k].attrs]
    keyfn = lambda f: f.entity_key
    return {"added": sorted(added, key=keyfn),
            "removed": sorted(removed, key=keyfn),
            "changed": sorted(changed, key=keyfn)}
