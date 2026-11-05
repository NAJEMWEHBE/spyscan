from __future__ import annotations
import ntpath
import os

from spyscan import powershell
from spyscan.allowlist import is_microsoft_signer

# Statuses that say nothing about the FILE's signature: the probe could not read
# it ('' = file missing / PowerShell printed only the separator) or cannot judge
# this file type. These are UNKNOWN (None), never unsigned (audit #10).
# UnknownError is deliberately NOT here: it is what an untrusted (e.g.
# self-signed) chain returns, which is exactly an implant's "unverified".
_NO_VERDICT = frozenset({"", "notsupportedfileformat"})

_UNKNOWN = {"signed": None, "verified": None, "status": "error",
            "signer": "", "trusted_ms": False}


def parse_status(line: str) -> dict:
    """line = '<Status>|<SignerSubject>' from Get-AuthenticodeSignature."""
    status, _, signer = (line or "").partition("|")
    status = status.strip()
    signer = signer.strip()
    if status.lower() in _NO_VERDICT:
        return {**_UNKNOWN, "status": status or "unknown"}
    signed = status.lower() == "valid"
    # exact Microsoft subjects only: "contains microsoft" also matched the Hardware
    # Compatibility Publisher, which signs third-party drivers (audit #4)
    trusted_ms = signed and is_microsoft_signer(signer)
    # verified mirrors signed: True only when Authenticode Status == Valid.
    return {"signed": signed, "verified": signed, "status": status,
            "signer": signer, "trusted_ms": trusted_ms}


def resolve_image(path: str) -> str:
    """The real on-disk file a fact's image path names, or '' if none is found.

    Registry values are REG_EXPAND_SZ (``%windir%\\...``) and Winlogon/Run entries
    often name a bare program (``explorer.exe``, ``rundll32.exe``) that Windows
    finds on its own search path. Bare names are looked up in the Windows dir,
    System32 and PATH -- never the current directory (a planted file there must
    not stand in for the real one).
    """
    p = os.path.expandvars(str(path or "").strip().strip('"'))
    if not p:
        return ""
    if ntpath.dirname(p):
        return p if os.path.isfile(p) else ""
    names = [p] if "." in p else [p, p + ".exe"]
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or ""
    dirs = [ntpath.join(root, "System32"), root] if root else []
    dirs += [d for d in os.environ.get("PATH", "").split(os.pathsep) if d and d != "."]
    for d in dirs:
        for n in names:
            cand = ntpath.join(d, n)
            if os.path.isfile(cand):
                return cand
    return ""


def authenticode(path: str) -> dict:         # impure edge
    # The path goes to PowerShell as DATA (spyscan.powershell), never as script
    # text: NTFS names may hold ' ; and the typographic quotes PowerShell also
    # treats as quotes, so interpolation is command injection in the scanner's
    # (often elevated) context.
    target = resolve_image(path)
    if not target:
        # Nothing on disk to look at: UNKNOWN, not unsigned (a failed probe must
        # score the same as no probe on the signature axis).
        return dict(_UNKNOWN)
    ps = ("$s=Get-AuthenticodeSignature -LiteralPath $data;"
          "\"$($s.Status)|$($s.SignerCertificate.Subject)\"")
    out = powershell.run(ps, target, timeout=20)
    # A timeout / PowerShell error comes back as b"" -> parse_status('') -> unknown.
    return parse_status(out.decode("utf-8-sig", errors="replace").strip())
