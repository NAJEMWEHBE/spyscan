import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest


@pytest.fixture(autouse=True)
def _no_live_security_log(monkeypatch):
    """Never read the real Security event log from a test: the canary collector
    asks for 4663 events on every gather. Tests that need events fake them."""
    from spyscan import canary_audit
    monkeypatch.setattr(canary_audit, "_wevtutil_runner", lambda paths, since: "")
