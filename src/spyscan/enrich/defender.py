# src/spyscan/enrich/defender.py
from __future__ import annotations
import re
import subprocess

# A threat name looks like  Category:Platform/Family[.Variant][!suffix]
# e.g. Trojan:Win32/Wacatac.B!ml , Trojan:Win32/Meterpreter
_THREAT_RE = re.compile(r"\b([A-Za-z][\w\-]*:[A-Za-z0-9]+/[\w\.\!\-@]+)")

_CLEAN_MARKERS = ("no threats", "found 0 threats", "0 threats")


def parse_status(out: str) -> dict:
    """Pure parser over Get-MpThreat / MpCmdRun output.

    Returns {"defender_hit": bool, "threat": str}. A hit is any line that
    contains a Defender threat-name token (Category:Platform/Family...), unless
    the output is an explicit clean/no-threats result.
    """
    text = (out or "").strip()
    if not text:
        return {"defender_hit": False, "threat": ""}

    low = text.lower()
    if any(m in low for m in _CLEAN_MARKERS):
        return {"defender_hit": False, "threat": ""}

    m = _THREAT_RE.search(text)
    if m:
        return {"defender_hit": True, "threat": m.group(1).strip()}

    return {"defender_hit": False, "threat": ""}


def scan_file(path: str) -> dict:                # impure edge (best-effort)
    """On-demand single-file scan via the built-in MpCmdRun.exe.

    Best-effort: returns no-hit on any error.
    """
    mpcmd = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    try:
        out = subprocess.run([mpcmd, "-Scan", "-ScanType", "3", "-File", path],
                             capture_output=True, text=True, timeout=120)
        return parse_status(out.stdout.strip())
    except Exception:
        return {"defender_hit": False, "threat": ""}
