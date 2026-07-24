# tests/test_diff.py
from spyscan.facts import Fact
from spyscan.diff import diff_facts

def f(key, **attrs):
    return Fact("c", key, "autostart", key, attrs)

def test_added_removed_changed():
    base = [f("a", path="x"), f("b", path="y")]
    curr = [f("b", path="CHANGED"), f("c", path="z")]
    d = diff_facts(base, curr)
    assert {x.entity_key for x in d["added"]} == {"c"}
    assert {x.entity_key for x in d["removed"]} == {"a"}
    assert [x.entity_key for x in d["changed"]] == ["b"]

def test_identical_baseline_is_clean():
    base = [f("a", path="x")]
    d = diff_facts(base, list(base))
    assert d == {"added": [], "removed": [], "changed": []}
