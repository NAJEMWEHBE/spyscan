# src/spyscan/enrich/defender.py
from __future__ import annotations
import re
import subprocess

# A threat name looks like  Category:Platform/Family[.Variant][!suffix]
# e.g. Trojan:Win32/Wacatac.B!ml , Trojan:Win32/Meterpreter
_THREAT_RE = re.compile(r"\b([A-Za-z][\w\-]*:[A-Za-z0-9]+/[\w\.\!\-@]+)")

# Anchored: "found 10 threats" must NOT read as the clean "0 threats" (audit #14).
_CLEAN_RE = re.compile(r"\bno threats\b|(?<![\d,.])\b0 threats\b", re.IGNORECASE)

# MpCmdRun -Scan exit codes: 0 = no threats, 2 = threats found.
_EXIT_THREATS_FOUND = 2


def parse_status(out: str, returncode: int | None = None) -> dict:
    """Pure parser over Get-MpThreat / MpCmdRun output (+ its exit code).

    Returns {"defender_hit": bool, "threat": str}. A hit is exit code 2, or any
    line that contains a Defender threat-name token (Category:Platform/Family...)
    unless the output is an explicit clean/no-threats result.
    """
    text = (out or "").strip()
    m = _THREAT_RE.search(text)
    if returncode == _EXIT_THREATS_FOUND:
        return {"defender_hit": True,
                "threat": m.group(1).strip() if m else "threat (name not reported)"}
    if not text or _CLEAN_RE.search(text):
        return {"defender_hit": False, "threat": ""}
    if m:
        return {"defender_hit": True, "threat": m.group(1).strip()}
    return {"defender_hit": False, "threat": ""}


def scan_file(path: str) -> dict:                # impure edge (best-effort)
    """On-demand single-file scan via the built-in MpCmdRun.exe.

    -DisableRemediation: report only. Defender's default action on a hit is to
    quarantine the file, which destroys the evidence a survivor may need and can
    tip off whoever planted it (audit #14). spyscan only ever looks.

    Best-effort: returns no-hit on any error.
    """
    mpcmd = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    try:
        out = subprocess.run([mpcmd, "-Scan", "-ScanType", "3", "-File", path,
                              "-DisableRemediation"],
                             capture_output=True, text=True, timeout=120)
        return parse_status(out.stdout.strip(), out.returncode)
    except Exception:
        return {"defender_hit": False, "threat": ""}
