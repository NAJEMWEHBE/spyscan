"""Docs drift (audit): the README must describe the score the code computes."""
from pathlib import Path

from spyscan.facts import Fact
from spyscan.score import score_fact

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")


def test_no_capped_0_to_100_score_or_beaconing_claim():
    # score_fact adds points with no cap, and nothing detects beaconing
    assert "0–100" not in README and "0-100" not in README
    assert "beaconing" not in README


def test_the_reading_results_example_is_a_real_reason_list():
    f = Fact("autostart_native", "k", "autostart", "x",
             {"is_new": True, "signed": False, "from_temp": True})
    reasons = ", ".join(score_fact(f)["reasons"])
    assert f"`{reasons}`" in README


def test_the_microsoft_floor_exceptions_are_documented():
    assert "Hardware Compatibility Publisher" in README
    assert "script host" in README
