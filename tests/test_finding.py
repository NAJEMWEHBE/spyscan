# tests/test_finding.py
import json
import pytest
from spyscan.facts import Fact
from spyscan.finding import Finding


def _f(bucket, score=0):
    return Finding(fact=Fact("processes", "processes::x::x", "process", "x",
                             {"is_new": True}),
                   score=score, bucket=bucket, reasons=["+3 new"], attack_id="T1055")


def test_is_actionable_alert_and_review():
    assert _f("ALERT").is_actionable() is True
    assert _f("REVIEW").is_actionable() is True


def test_is_actionable_info_collapsed():
    assert _f("INFO").is_actionable() is False


def test_to_from_dict_round_trip():
    # parse(build(x)) == x for the serialized (JSON) shape -- the owning adapter
    # owns both directions; this is its own inverse property, not a drift-guard.
    f = _f("ALERT", 9)
    assert Finding.from_dict(f.to_dict()) == f


def test_to_dict_is_json_serializable():
    json.dumps(_f("REVIEW", 5).to_dict())  # must not raise
