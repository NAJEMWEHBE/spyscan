# ADR 0002 -- the entity-identity contract's core mechanics.
from spyscan.facts import Fact
from spyscan.diff import diff_facts
from spyscan.store import BaselineStore


def test_observed_round_trips_through_store(tmp_path):
    f = Fact("processes", "processes::a.exe::c:\\a.exe", "process", "a.exe",
             attrs={"exe": r"C:\a.exe"}, observed={"pids": [1, 2], "instance_count": 2})
    store = BaselineStore(tmp_path / "b.db")
    store.save_baseline([f])
    (loaded,) = store.load_baseline()
    assert loaded == f
    assert loaded.observed == {"pids": [1, 2], "instance_count": 2}


def test_old_baseline_without_observed_loads_fine():
    d = {"collector": "x", "entity_key": "x::k", "kind": "process",
         "label": "l", "attrs": {"exe": "e"}, "attack_id": None}
    f = Fact.from_dict(d)                       # pre-ADR-0002 baseline row shape
    assert f.observed == {}


def test_diff_is_blind_to_observed():
    base = [Fact("netconns", "netconns::p::1.2.3.4:443", "connection", "p",
                 attrs={"remote_ip": "1.2.3.4"}, observed={"conn_count": 3, "pids": [1]})]
    curr = [Fact("netconns", "netconns::p::1.2.3.4:443", "connection", "p",
                 attrs={"remote_ip": "1.2.3.4"}, observed={"conn_count": 91, "pids": [7, 9]})]
    d = diff_facts(base, curr)
    assert [len(d["added"]), len(d["removed"]), len(d["changed"])] == [0, 0, 0]


def test_diff_still_fires_on_attr_change():
    base = [Fact("drivers", "drivers::acpi", "driver", "acpi",
                 attrs={"path": r"C:\old\acpi.sys"}, observed={"state": "Running"})]
    curr = [Fact("drivers", "drivers::acpi", "driver", "acpi",
                 attrs={"path": r"C:\new\acpi.sys"}, observed={"state": "Running"})]
    assert len(diff_facts(base, curr)["changed"]) == 1
