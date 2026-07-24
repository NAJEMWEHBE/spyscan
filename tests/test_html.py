# tests/test_html.py
from spyscan.report.html import render_html
from spyscan.report.json_out import render_json
import json
from spyscan.finding import Finding
from spyscan.facts import Fact


def _finding(label, collector, score, bucket, reasons=None, attack_id=None):
    return Finding(fact=Fact(collector, f"{collector}::{label}::{label}",
                             "process", label, {}),
                   score=score, bucket=bucket,
                   reasons=reasons or [], attack_id=attack_id)


def test_html_has_verdict_and_escapes():
    findings = [_finding("<b>bh</b>", "processes", 10, "ALERT",
                         ["+5 implant daemon"], "T1125")]
    html = render_html(findings, meta={"host": "PC", "when": "2026-06-29"})
    assert "ALERT" in html
    assert "&lt;b&gt;bh&lt;/b&gt;" in html          # escaped, not raw tag
    assert "<b>bh</b>" not in html                  # raw tag must NOT appear
    assert "not a kernel EDR" in html.lower() or "clean result" in html.lower()


def test_verdict_clean_when_no_alerts():
    html = render_html([_finding("x", "c", 1, "INFO")],
                       meta={"host": "PC", "when": "now"})
    assert "No high-risk" in html or "likely clean" in html.lower()


def test_verdict_alert_when_any_alert():
    findings = [
        _finding("bh", "processes", 10, "ALERT"),
        _finding("ok", "c", 1, "INFO"),
    ]
    html = render_html(findings, meta={"host": "PC", "when": "now"})
    assert "class='v ALERT'" in html or 'class="v ALERT"' in html


def test_table_shows_only_alert_and_review_rows():
    findings = [
        _finding("ALERTROW", "processes", 10, "ALERT"),
        _finding("REVIEWROW", "processes", 5, "REVIEW"),
        _finding("INFOROW", "processes", 1, "INFO"),
    ]
    html = render_html(findings, meta={"host": "PC", "when": "now"})
    assert "ALERTROW" in html
    assert "REVIEWROW" in html
    assert "INFOROW" not in html                    # INFO not rendered as a row


def test_info_collapsed_to_count_line():
    findings = [
        _finding("A", "c", 10, "ALERT"),
    ] + [
        _finding(f"info{i}", "c", 1, "INFO")
        for i in range(4365)
    ]
    html = render_html(findings, meta={"host": "PC", "when": "now"})
    assert "4365 informational" in html
    assert "info0" not in html                       # the 4365 rows are NOT dumped


def test_table_sorted_by_score_desc():
    findings = [
        _finding("LOW", "c", 4, "REVIEW"),
        _finding("HIGH", "c", 12, "ALERT"),
    ]
    html = render_html(findings, meta={"host": "PC", "when": "now"})
    assert html.index("HIGH") < html.index("LOW")


def test_render_json_keeps_full_findings_including_info():
    findings = [
        _finding("A", "c", 10, "ALERT"),
        _finding("info0", "c", 1, "INFO"),
    ]
    out = render_json(findings, {"host": "PC", "when": "now"})
    parsed = json.loads(out)
    assert len(parsed["findings"]) == 2              # INFO retained in JSON
    labels = {f["fact"]["label"] for f in parsed["findings"]}
    assert "info0" in labels
    assert parsed["meta"]["host"] == "PC"


def test_honest_limits_footer_present():
    html = render_html([], meta={"host": "PC", "when": "now"})
    low = html.lower()
    assert "usermode" in low
    assert "not a kernel edr" in low
    assert "local-only" in low or "no data left" in low
