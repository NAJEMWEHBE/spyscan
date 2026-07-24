# src/spyscan/report/json_out.py
from __future__ import annotations
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from spyscan.finding import Finding


def render_json(findings: list[Finding], meta: dict) -> str:
    """Full findings list (ALL buckets incl. INFO) for completeness/audit.

    Serializes each Finding through its own ``to_dict`` (the owning adapter), so
    the on-disk JSON shape has exactly one producer."""
    return json.dumps({"meta": meta,
                       "findings": [f.to_dict() for f in findings]}, indent=2)
