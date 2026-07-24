# tests/test_observed_rules.py
# ADR 0002 follow-up: observed is diff-blind, but two transitions are read back
# deliberately as weak (+1) evidence -- pipeline.observed_deltas + score_fact.
from spyscan.facts import Fact
from spyscan.rules.ioc import IOCMatcher
from spyscan.pipeline import build_findings, observed_deltas


def _proc(n_instances, **attrs):
    return Fact("processes", "processes::a.exe::c:\\tools\\a.exe", "process",
                "a.exe", {"exe": r"C:\Tools\a.exe", **attrs},
                observed={"pids": list(range(n_instances)),
                          "instance_count": n_instances,
                          "parents": ["services.exe"], "cmdlines": []})


def _drv(state, **attrs):
    return Fact("drivers", "drivers::xdrv", "driver", "xdrv",
                {"path": r"C:\Windows\System32\drivers\xdrv.sys", **attrs},
                observed={"state": state, "status": "OK"})


def _find(base, current):
    by_key = {f.fact.entity_key: f
              for f in build_findings(base, current, IOCMatcher())}
    return by_key[current[0].entity_key]


# --- process: instance count 1 -> N ------------------------------------------

def test_single_to_multi_fires_plus_one():
    top = _find([_proc(1)], [_proc(3)])
    assert top.fact.attrs["instances_grew"] == "1->3"
    assert top.score == 1
    assert any("instance count grew 1->3" in r for r in top.reasons)


def test_multi_to_multi_churn_is_silent():
    top = _find([_proc(83)], [_proc(85)])
    assert "instances_grew" not in top.fact.attrs
    assert top.score == 0


def test_shrink_and_steady_are_silent():
    assert "instances_grew" not in _find([_proc(3)], [_proc(1)]).fact.attrs
    assert "instances_grew" not in _find([_proc(1)], [_proc(1)]).fact.attrs


def test_new_process_has_no_delta():
    # no baseline entry -> nothing to compare; is_new carries the signal instead
    top = _find([], [_proc(3)])
    assert "instances_grew" not in top.fact.attrs
    assert top.fact.attrs["is_new"] is True


def test_legacy_baseline_without_observed_is_silent():
    old = Fact("processes", "processes::a.exe::c:\\tools\\a.exe", "process",
               "a.exe", {"exe": r"C:\Tools\a.exe"})  # pre-ADR-0002: observed={}
    assert "instances_grew" not in _find([old], [_proc(3)]).fact.attrs


# --- driver: Stopped -> Running ----------------------------------------------

def test_dormant_driver_started_fires_plus_one():
    top = _find([_drv("Stopped")], [_drv("Running")])
    assert top.fact.attrs["driver_started"] is True
    assert top.score == 1
    assert any("driver started since baseline" in r for r in top.reasons)


def test_running_to_running_is_silent():
    assert "driver_started" not in _find([_drv("Running")], [_drv("Running")]).fact.attrs


def test_running_to_stopped_is_silent():
    assert "driver_started" not in _find([_drv("Running")], [_drv("Stopped")]).fact.attrs


def test_legacy_driver_baseline_is_silent():
    old = Fact("drivers", "drivers::xdrv", "driver", "xdrv",
               {"path": r"C:\Windows\System32\drivers\xdrv.sys"})
    assert "driver_started" not in _find([old], [_drv("Running")]).fact.attrs


# --- unit: observed_deltas edge shapes ---------------------------------------

def test_no_baseline_fact_returns_empty():
    assert observed_deltas(None, _proc(5)) == {}


def test_delta_composes_with_real_signals():
    # +1 alone stays INFO; combined with unsigned (+2) and no resolvable
    # parent (+2) it crosses into REVIEW -- the intended escalation shape.
    # Baseline attrs are IDENTICAL (only observed differs) so is_new stays False:
    # this is the pure "known binary suddenly has an orphan twin" scenario.
    base = Fact("processes", "processes::a.exe::c:\\tools\\a.exe", "process",
                "a.exe", {"exe": r"C:\Tools\a.exe", "signed": False},
                observed={"pids": [1], "instance_count": 1,
                          "parents": ["services.exe"], "cmdlines": []})
    cur = Fact("processes", "processes::a.exe::c:\\tools\\a.exe", "process",
               "a.exe", {"exe": r"C:\Tools\a.exe", "signed": False},
               observed={"pids": [1, 2], "instance_count": 2,
                         "parents": [""], "cmdlines": []})
    top = _find([base], [cur])
    assert top.fact.attrs["is_new"] is False
    assert top.score == 5 and top.bucket == "REVIEW"
