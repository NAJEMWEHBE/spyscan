# src/spyscan/report/html.py
from __future__ import annotations
from html import escape
from spyscan.finding import Finding
from spyscan.score import Bucket

_CSS = "body{font:14px system-ui;margin:2rem;background:#0b0f14;color:#dfe7ef}" \
       "h1{margin:0}.v{padding:1rem;border-radius:8px;font-weight:700;margin:1rem 0}" \
       ".ALERT{background:#5a1620;color:#ffd7dd}.REVIEW{background:#5a4416;color:#ffe7b3}" \
       ".INFO{background:#16304a;color:#cfe6ff}table{width:100%;border-collapse:collapse}" \
       "td,th{border-bottom:1px solid #25303c;padding:.4rem;text-align:left;vertical-align:top}" \
       ".info-note{margin:1rem 0;color:#8aa}.foot{margin-top:2rem;color:#8aa;font-size:12px}"


def _verdict(findings):
    """Verdict banner = worst bucket present across ALL findings (unchanged)."""
    if any(f.bucket == Bucket.ALERT for f in findings):
        return Bucket.ALERT, "Suspicious activity found - review the ALERT rows below."
    if any(f.bucket == Bucket.REVIEW for f in findings):
        return Bucket.REVIEW, "Some items warrant a look. No high-confidence spyware signal."
    return Bucket.INFO, "No high-risk findings - device likely clean (see limits below)."


def render_html(findings: list[Finding], meta: dict) -> str:
    vb, vmsg = _verdict(findings)

    # The TABLE lists only ALERT + REVIEW, sorted by score desc.
    # INFO is NOT dumped as rows (a clean live scan yields thousands of benign
    # INFO facts) - it is collapsed into one aggregate count line.
    shown = sorted((f for f in findings if f.is_actionable()),
                   key=lambda x: x.score, reverse=True)
    info_count = sum(1 for f in findings if f.bucket == Bucket.INFO)

    rows = []
    for f in shown:
        fact = f.fact
        rows.append(
            f"<tr><td class='{f.bucket}'>{f.bucket} ({f.score})</td>"
            f"<td>{escape(str(fact.label))}</td>"
            f"<td>{escape(str(fact.collector))}</td>"
            f"<td>{escape(', '.join(f.reasons))}</td>"
            f"<td>{escape(str(f.attack_id or ''))}</td></tr>")

    if rows:
        table = (f"<table><tr><th>Risk</th><th>Entity</th><th>Source</th>"
                 f"<th>Why</th><th>ATT&CK</th></tr>{''.join(rows)}</table>")
    else:
        table = "<p class='info-note'>No ALERT or REVIEW findings.</p>"

    info_note = (f"<p class='info-note'>{info_count} informational item"
                 f"{'' if info_count == 1 else 's'} not shown "
                 f"(benign / below review threshold).</p>") if info_count else ""

    foot = ("This is a usermode scanner/triage tool - <b>not a kernel EDR</b>. "
            "It can miss kernel-hidden or zero-click implants. A clean result is "
            "<b>not</b> proof the device is clean. Local-only; no data left this machine.")

    return (f"<!doctype html><meta charset=utf-8><style>{_CSS}</style>"
            f"<h1>spyscan report</h1><div>{escape(str(meta.get('host', '')))} - "
            f"{escape(str(meta.get('when', '')))}</div>"
            f"<div class='v {vb}'>{vb}: {escape(vmsg)}</div>"
            f"{table}{info_note}"
            f"<p class='foot'>{foot}</p>")
