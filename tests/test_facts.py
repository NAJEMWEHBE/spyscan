# tests/test_facts.py
from spyscan.facts import Fact, make_key

def test_make_key_is_stable_and_namespaced():
    k1 = make_key("autoruns", "HKLM\\Run", "Updater")
    k2 = make_key("autoruns", "HKLM\\Run", "Updater")
    assert k1 == k2
    assert k1.startswith("autoruns::")

def test_fact_to_dict_roundtrip():
    f = Fact(collector="autoruns", entity_key="autoruns::a::b",
             kind="autostart", label="Updater", attrs={"path": "c:\\u.exe"},
             attack_id="T1547.001")
    d = f.to_dict()
    assert d["attack_id"] == "T1547.001"
    assert Fact.from_dict(d) == f
