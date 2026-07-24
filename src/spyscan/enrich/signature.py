from __future__ import annotations
import os
import subprocess

def parse_status(line: str) -> dict:
    """line = '<Status>|<SignerSubject>' from Get-AuthenticodeSignature."""
    status, _, signer = line.partition("|")
    status = status.strip()
    signer = signer.strip()
    signed = status.lower() == "valid"
    trusted_ms = signed and "microsoft" in signer.lower()
    # verified mirrors signed: True only when Authenticode Status == Valid.
    return {"signed": signed, "verified": signed, "status": status,
            "signer": signer, "trusted_ms": trusted_ms}

def authenticode(path: str) -> dict:         # impure edge
    # Pass the scanned path out-of-band via an env var and read it inside PowerShell as
    # $env:SPYSCAN_TARGET. NTFS leaf names may legally contain ' and ; so interpolating
    # `path` into a quoted -Command string is command injection: a process/autostart image
    # named e.g.  a'; <payload>; '.exe  would break out and execute arbitrary PowerShell in
    # the scanner's (often elevated) context. The env route never reaches the PS parser.
    ps = ("$s=Get-AuthenticodeSignature -LiteralPath $env:SPYSCAN_TARGET;"
          "\"$($s.Status)|$($s.SignerCertificate.Subject)\"")
    try:
        env = dict(os.environ, SPYSCAN_TARGET=path)
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=20, env=env)
        return parse_status(out.stdout.strip())
    except Exception:
        # The probe could not run (timeout / PowerShell error). This is UNKNOWN, not
        # unsigned: signed=None so score_fact's `is False` penalty is skipped and a
        # genuinely MS-signed binary whose probe timed out is not falsely flagged. A
        # failed probe must score the same as no probe on the signature axis.
        return {"signed": None, "verified": None, "status": "error",
                "signer": "", "trusted_ms": False}
