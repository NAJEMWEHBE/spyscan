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
from fnmatch import fnmatch
from pathlib import Path

# Fact attrs that hold an on-disk image path (tested against path_globs).
_PATH_ATTRS = ("exe", "image_path", "image", "path")


def _is_ms_signed(attrs: dict) -> bool:
    """True if a fact is Microsoft-signed AND its signature verified -- the built-in
    known-good floor folded in from score.py (ADR 0001). Verified-gating is load-bearing:
    an UNVERIFIED fact whose signer merely claims 'Microsoft' must NOT floor (spoofed-cert
    bypass). Mirrors score.py's old condition exactly, incl. the cross-collector `or`
    (enriched facts set trusted_ms; autoruns facts set verified+signer but not trusted_ms)."""
    if attrs.get("trusted_ms"):
        return True
    if attrs.get("verified") and "microsoft" in str(attrs.get("signer", "")).lower():
        return True
    return False


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
