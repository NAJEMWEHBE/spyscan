# tests/test_cli_phase0.py
from spyscan import cli  # noqa
from spyscan.facts import Fact
from spyscan.store import BaselineStore
from spyscan.diff import diff_facts

def test_scan_flags_new_autostart(tmp_path):
    store = BaselineStore(tmp_path / "b.db")
    base = [Fact("autoruns", "autoruns::HKLM::A", "autostart", "A", {"verified": True})]
    store.save_baseline(base)
    current = base + [Fact("autoruns", "autoruns::HKCU::Evil", "autostart",
                           "Evil", {"verified": False, "image_path": "c:\\temp\\e.exe"})]
    d = diff_facts(store.load_baseline(), current)
    assert [x.entity_key for x in d["added"]] == ["autoruns::HKCU::Evil"]
