# src/spyscan/powershell.py
"""The one way spyscan runs PowerShell: constant script text, data out-of-band.

Every value that comes from the scanned machine (file paths, shortcut names,
registry data) is attacker-influenced. Splicing it into a ``-Command`` string is
command injection, and escaping cannot be made reliable: PowerShell treats the
typographic quotes U+2018/U+2019/U+201A/U+201B as single quotes, so a Startup
shortcut named ``a<U+2019>;<payload>;<U+2019>b.lnk`` escapes an ASCII-only ``''``
escape (audit #1).

So the script text here is always a constant written by spyscan, and the data
travels on stdin as ASCII-only JSON (``ensure_ascii`` -> ``\\uXXXX`` escapes, so the
console code page can never mangle a non-ASCII path). The script sees it as
``$data``. Output is forced to UTF-8 so non-ASCII paths come back intact.
"""
from __future__ import annotations
import json
import subprocess

# Prepended to every script. UTF-8 output; $data parsed from stdin JSON.
_PRELUDE = ("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "$data = [Console]::In.ReadToEnd() | ConvertFrom-Json; ")


def encode_data(data) -> bytes:
    """ASCII-only JSON bytes for ``data`` (what goes on PowerShell's stdin)."""
    return json.dumps(data, ensure_ascii=True).encode("ascii")


def run(script: str, data=None, *, timeout: float = 60) -> bytes:
    """Run ``script`` (constant text) with ``data`` available as ``$data``.

    Returns stdout bytes (UTF-8), or b"" on any failure (PowerShell missing,
    timeout). Never raises: every caller treats empty output as 'no signal'.
    """
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PRELUDE + script],
            input=encode_data(data), capture_output=True, timeout=timeout)
        return out.stdout or b""
    except Exception:
        return b""
