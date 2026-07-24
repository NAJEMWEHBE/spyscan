# tests/test_store.py
from spyscan.facts import Fact
from spyscan.store import BaselineStore

def test_save_and_load_roundtrip(tmp_path):
    db = tmp_path / "b.db"
    s = BaselineStore(db)
    facts = [Fact("autoruns", "autoruns::a::b", "autostart", "X", {"path": "c:\\x"}, "T1547.001")]
    s.save_baseline(facts)
    loaded = s.load_baseline()
    assert loaded == facts

def test_load_empty_returns_empty_list(tmp_path):
    s = BaselineStore(tmp_path / "none.db")
    assert s.load_baseline() == []
