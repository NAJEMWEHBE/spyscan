# src/spyscan/allowlist.py
"""Owner of every known-good floor: user rules AND a built-in Microsoft rule.

A small, explicit set of rules that floor a benign fact toward INFO so the
user's own trusted software (their dev interpreters, signed vendor tools)
stops raising ALERTs. In addition to the user-editable rules, it now owns a
built-in, always-active *verified Microsoft-signed* floor folded here from
score.py (ADR 0001), so allowlist.py is the single home of the "which
known-good floors exist?" policy and the Microsoft floor is finally inspectable
(see builtin_rules()). It is a NON-security gate: scoring applies it ONLY when
no known-bad signal is present, so it can never hide real malware (see
score.py). Loading a missing file yields an empty *user* allowlist -- the
built-in Microsoft floor still applies -- and the scan never crashes on a
bad/absent config.
"""
from __future__ import annotations
import json
import ntpath
import re
from fnmatch import fnmatch
from pathlib import Path

from spyscan.facts import IMAGE_PATH_ATTRS, image_path_of
from spyscan.collectors.base import is_tempish

# Fact attrs that hold an on-disk image path (tested against path_globs). The ONE
# list lives in facts.py and is shared with the enrichment pass (audit #2).
_PATH_ATTRS = IMAGE_PATH_ATTRS

# Signer common names that ARE Microsoft's own code. Exact match, not "contains
# microsoft": the Hardware Compatibility Publisher (WHQL/attestation signing) and
# the 3rd Party Application Component cert sign OTHER vendors' code (malicious
# attestation-signed drivers exist), and any vendor can put "Microsoft" in its
# own name (audit #4).
_MS_SIGNER_CNS = frozenset({
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
    "microsoft windows early launch anti-malware publisher",
})
_CN_RE = re.compile(r'(?:^|,)\s*CN\s*=\s*("?)([^,"]+)\1', re.IGNORECASE)

# Microsoft-signed hosts whose job is to run SOMETHING ELSE (a script, a DLL, a
# command line). Their signature says nothing about the payload, so with any
# argument they get no Microsoft floor and are scored on their other signals.
_SCRIPT_HOSTS = frozenset({
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
})


def is_microsoft_signer(signer: str) -> bool:
    """True if a signer string ('Microsoft Windows' or a full X.500 subject
    'CN=Microsoft Windows, O=...') names one of Microsoft's own signing certs."""
    s = str(signer or "").strip()
    m = _CN_RE.search(s)
    cn = m.group(2) if m else s
    return cn.strip().lower() in _MS_SIGNER_CNS


def _host_name(path: str) -> str:
    """'C:/Windows/System32/cmd.exe' -> 'cmd'; 'powershell' -> 'powershell'."""
    base = ntpath.basename(str(path or "").strip().strip('"')).lower()
    return base[:-4] if base.endswith(".exe") else base


def _args_after(cmd: str, host: str) -> str:
    """Whatever a command line passes AFTER the host program ('' if nothing)."""
    c = str(cmd or "").strip()
    # the host as the program token: 'cmd', 'cmd.exe', '...\cmd.exe"' followed by
    # a space or the end -- never a substring of a folder ('WindowsPowerShell\')
    m = re.search(re.escape(host) + r'(?:\.exe)?"?(?=\s|$)', c, re.IGNORECASE)
    return c[m.end():].strip() if m else ""


def _runs_foreign_payload(attrs: dict) -> bool:
    """True when what the entry RUNS is not just the signed binary itself: a
    script/proxy host given any argument, or a launch string that reaches into a
    temp/AppData path the image itself is not in (audit #4)."""
    image = image_path_of(attrs)
    launches = [str(attrs.get("launch_string") or "")] + [
        str(c) for c in (attrs.get("cmdlines") or [])]
    host = _host_name(image)
    if host in _SCRIPT_HOSTS and any(_args_after(l, host) for l in launches):
        return True
    if not is_tempish(image) and any(is_tempish(l) for l in launches):
        return True
    return False


def _is_ms_signed(attrs: dict) -> bool:
    """True if a fact is Microsoft-signed AND its signature verified AND it runs
    only itself -- the built-in known-good floor folded in from score.py (ADR
    0001). Verified-gating is load-bearing: an UNVERIFIED fact whose signer merely
    claims 'Microsoft' must NOT floor (spoofed-cert bypass). The cross-collector
    `or` stays (enriched facts set trusted_ms; autoruns facts set verified+signer
    but not trusted_ms)."""
    signed_by_ms = bool(attrs.get("trusted_ms")) or bool(
        attrs.get("verified") and is_microsoft_signer(attrs.get("signer", "")))
    return signed_by_ms and not _runs_foreign_payload(attrs)


class Allowlist:
    def __init__(self, signers=None, path_globs=None, sha256=None, entity_keys=None):
        # signers: substring match, case-insensitive
        self.signers = [s.lower() for s in (signers or []) if s]
        # path_globs: fnmatch over a lowercased image path
        self.path_globs = [g.lower() for g in (path_globs or []) if g]
        # sha256: a hash set (also tested against a fact's md5), case-insensitive
        self.sha256 = {h.lower() for h in (sha256 or []) if h}
        # entity_keys: exact namespaced-key match
        self.entity_keys = set(entity_keys or [])

    @classmethod
    def load(cls, path) -> "Allowlist":
        """Load rules from a JSON file. A missing/unreadable/malformed file
        returns an empty allowlist (never raises) so the scan can't crash."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return cls()
        if not isinstance(data, dict):
            return cls()
        return cls(
            signers=data.get("signers"),
            path_globs=data.get("path_globs"),
            sha256=data.get("sha256"),
            entity_keys=data.get("entity_keys"),
        )

    def matches(self, attrs: dict) -> tuple[bool, str]:
        """Return (True, "allowlisted: <rule + value>") if any rule matches the
        fact's attrs, else (False, "")."""
        # path_globs over exe/image_path (lowercased fnmatch)
        for key in _PATH_ATTRS:
            val = (attrs.get(key) or "").strip()
            if not val:
                continue
            low = val.lower()
            for g in self.path_globs:
                if fnmatch(low, g):
                    return True, f"allowlisted: path_glob '{g}' matched {val}"

        # signer substring
        signer = str(attrs.get("signer") or "")
        if signer:
            sl = signer.lower()
            for s in self.signers:
                if s in sl:
                    return True, f"allowlisted: signer '{s}' in {signer}"

        # sha256 / md5 against the hash set
        for hkey in ("sha256", "md5"):
            h = str(attrs.get(hkey) or "").lower()
            if h and h in self.sha256:
                return True, f"allowlisted: {hkey} {h}"

        # entity_key exact
        ek = attrs.get("entity_key")
        if ek and ek in self.entity_keys:
            return True, f"allowlisted: entity_key {ek}"

        # built-in known-good floor: verified Microsoft-signed (ADR 0001, folded from score.py).
        # Always active -- even for an empty/missing user allowlist -- so it preserves the old
        # unconditional score.py floor. score.py applies it only when no known-bad signal fires.
        if _is_ms_signed(attrs):
            return True, "allowlisted: Microsoft-signed"
        return False, ""

    def builtin_rules(self) -> list[str]:
        """Human-readable built-in (non-user-editable) known-good rules, for CLI/app
        display. Currently: the verified Microsoft-signed floor folded from score.py (ADR 0001)."""
        return ["Microsoft-signed (verified)"]
