# tests/test_defender_parse.py
from spyscan.enrich.defender import parse_status
from spyscan.facts import Fact
from spyscan.score import score_fact


def test_threat_name_means_hit():
    # `Get-MpThreat` prints a ThreatName line when something was detected
    out = "Trojan:Win32/Wacatac.B!ml"
    s = parse_status(out)
    assert s["defender_hit"] is True
    assert "Wacatac" in s["threat"]


def test_mpcmdrun_found_threats_line():
    out = ("Scanning C:\\Users\\n\\AppData\\Local\\Temp\\u.exe found 1 threats.\n"
           "Threat                  : Trojan:Win32/Meterpreter\n")
    s = parse_status(out)
    assert s["defender_hit"] is True
    assert "Meterpreter" in s["threat"]


def test_clean_output_is_no_hit():
    out = "Scan starting...\nScan finished.\nNo threats detected.\n"
    s = parse_status(out)
    assert s["defender_hit"] is False
    assert s["threat"] == ""


def test_empty_output_is_no_hit():
    s = parse_status("")
    assert s["defender_hit"] is False
    assert s["threat"] == ""


def test_whitespace_only_is_no_hit():
    s = parse_status("   \n  \n")
    assert s["defender_hit"] is False


def test_defender_hit_scores_plus5_via_score_fact():
    # proves the +5 wiring in score.py consumes the parser's defender_hit attr
    s = parse_status("Trojan:Win32/Wacatac.B!ml")
    f = Fact("autoruns", "autoruns::a::b", "autostart", "u.exe",
             {"verified": False, "defender_hit": s["defender_hit"], "threat": s["threat"]})
    r = score_fact(f)
    assert r["score"] >= 5
    assert any("defender" in why.lower() for why in r["reasons"])
