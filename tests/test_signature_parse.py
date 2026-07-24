from spyscan.enrich.signature import parse_status
def test_valid_microsoft():
    line = "Valid|Microsoft Windows"
    s = parse_status(line)
    assert s["signed"] is True and s["trusted_ms"] is True
def test_unsigned():
    s = parse_status("NotSigned|")
    assert s["signed"] is False and s["trusted_ms"] is False

# --- verified: True ONLY when Status == Valid (mirrors signed) ---
def test_valid_microsoft_is_verified():
    s = parse_status("Valid|Microsoft Windows")
    assert s["verified"] is True
def test_unsigned_is_not_verified():
    s = parse_status("NotSigned|")
    assert s["verified"] is False

# --- #12: a FAILED/timed-out Authenticode probe is UNKNOWN, not unsigned ---
# The probe returning a concrete signed=False on timeout penalizes a genuinely
# MS-signed binary (+2 unsigned, loses the MS floor) -> false ALERT. A failed
# probe must score the SAME as no probe on the signature axis (unknown = None).
import subprocess as _sp
from spyscan.enrich import signature as _sig

def test_authenticode_timeout_is_unknown_not_unsigned(monkeypatch):
    def boom(*a, **k):
        raise _sp.TimeoutExpired(cmd="powershell", timeout=20)
    monkeypatch.setattr(_sig.subprocess, "run", boom)
    r = _sig.authenticode("C:/some/where.exe")
    assert r["signed"] is None and r["verified"] is None   # unknown, NOT False
    assert r["trusted_ms"] is False                        # unknown -> no MS floor

def test_authenticode_error_is_unknown_not_unsigned(monkeypatch):
    def boom(*a, **k):
        raise OSError("powershell not found")
    monkeypatch.setattr(_sig.subprocess, "run", boom)
    r = _sig.authenticode("C:/some/where.exe")
    assert r["signed"] is None and r["verified"] is None
