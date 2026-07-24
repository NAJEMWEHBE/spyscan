from spyscan.collectors import COLLECTORS

def test_registry_lists_autoruns():
    assert "autoruns" in {c.name for c in COLLECTORS}
