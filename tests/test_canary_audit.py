# tests/test_canary_audit.py
"""UNIT 2 - best-effort Windows access auditing for canaries.

The PURE parser (read_access_events) is unit-tested against a fixture 4663
Security-log event. The live gather is best-effort: without SACL auditing +
admin it returns [] rather than crashing, so we only smoke-test that it never
raises and returns a list.
"""
from pathlib import Path

from spyscan import canary_audit

FIX = Path(__file__).parent / "fixtures"


def _sample_xml() -> str:
    return (FIX / "event_4663_sample.xml").read_text(encoding="utf-8")


def test_parser_extracts_process_and_path():
    events = canary_audit.read_access_events(
        paths=[r"C:\Users\TESTUSER\Desktop\passwords.txt"],
        since=None,
        runner=lambda *a, **k: _sample_xml(),
    )
    assert events, "parser found no matching 4663 events"
    e = events[0]
    # process name + accessed path extracted from the EventData
    assert e["process_name"].endswith("sneaky_stealer.exe")
    assert e["object_name"] == r"C:\Users\TESTUSER\Desktop\passwords.txt"
    assert e["event_id"] == 4663
    assert e["process_id"]  # carried through
    assert e["subject_user"] == "TESTUSER"
    assert e["time"].startswith("2026-06-30")


def test_parser_filters_to_requested_paths():
    # only ask about the Desktop canary -> the Documents event is excluded
    events = canary_audit.read_access_events(
        paths=[r"C:\Users\TESTUSER\Desktop\passwords.txt"],
        since=None,
        runner=lambda *a, **k: _sample_xml(),
    )
    names = {e["object_name"] for e in events}
    assert names == {r"C:\Users\TESTUSER\Desktop\passwords.txt"}


def test_parser_matches_multiple_paths_case_insensitive():
    events = canary_audit.read_access_events(
        paths=[r"c:\users\testuser\desktop\passwords.txt",
               r"C:\Users\TESTUSER\Documents\crypto_wallet_seed.txt"],
        since=None,
        runner=lambda *a, **k: _sample_xml(),
    )
    assert len(events) == 2


def test_parser_empty_on_no_paths():
    assert canary_audit.read_access_events(paths=[], since=None,
                                           runner=lambda *a, **k: _sample_xml()) == []


def test_parser_survives_garbage_output():
    # a non-XML / error string from the runner must not crash the parser
    out = canary_audit.read_access_events(
        paths=[r"C:\x"], since=None,
        runner=lambda *a, **k: "ERROR: access is denied.")
    assert out == []


def test_gather_is_best_effort_and_never_raises():
    # force the runner to blow up -> gather degrades to [] (no admin/SACL path)
    def boom(*a, **k):
        raise OSError("wevtutil not available")
    res = canary_audit.gather(paths=[r"C:\x\passwords.txt"], since=None, runner=boom)
    assert res == []


def test_parser_is_xxe_and_entity_bomb_safe():
    # defence-in-depth: a crafted event blob with a DOCTYPE/ENTITY (XXE or
    # billion-laughs) must be neutralised, not expanded, and must not crash.
    malicious = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE Events [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">'
        '<!ENTITY lol "lollol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>'
        '<Events><Event xmlns="http://x">'
        '<System><EventID>4663</EventID>'
        '<TimeCreated SystemTime="2026-06-30T00:00:00Z"/></System>'
        '<EventData>'
        '<Data Name="ObjectName">C:\\bait.txt</Data>'
        '<Data Name="ProcessName">&xxe;&lol2;</Data>'
        '</EventData></Event></Events>'
    )
    events = canary_audit.read_access_events(
        paths=[r"C:\bait.txt"], since=None, runner=lambda *a, **k: malicious)
    # parsed safely; the external entity was NOT resolved to file contents
    assert len(events) == 1
    assert "win.ini" not in events[0]["process_name"]
    assert "[" not in events[0]["process_name"]  # no win.ini section header leaked


def test_enable_audit_commands_are_printable_and_local():
    txt = canary_audit.enable_audit_commands([r"C:\Users\TESTUSER\Desktop\passwords.txt"])
    low = txt.lower()
    # mentions the two real mechanisms the user must enable as admin
    assert "auditpol" in low
    assert "set-acl" in low or "icacls" in low
    # must NOT try to elevate or call out to the network
    assert "runas" not in low
    assert "http://" not in low and "https://" not in low
