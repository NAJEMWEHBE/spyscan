from __future__ import annotations
from pathlib import Path

from spyscan.resources import resource_dir


def default_indicators_dir() -> Path:
    """Frozen-aware default location of the shipped IOC indicator lists.

    Dev -> ``src/spyscan/rules/indicators``; PyInstaller -> the bundled copy under
    ``<_MEIPASS>/spyscan/rules/indicators``. Callers that pass an explicit dir
    (CLI ``--ind`` / tests) bypass this.
    """
    return resource_dir("rules", "indicators")


class IOCMatcher:
    def __init__(self, domains: set[str] | None = None, procnames: set[str] | None = None):
        # strip('.') both ends so root-form FQDN feed entries ('evil.com.') match
        # hosts, which match_domain normalizes with rstrip('.') (symmetric). Drop
        # entries that normalize to '' (a malformed all-dots/empty feed line) -- an
        # empty domain would otherwise match an empty host string.
        self.domains = {n for d in (domains or set()) if (n := d.lower().strip("."))}
        self.procnames = {p.lower() for p in (procnames or set())}

    @classmethod
    def from_dir(cls, d: Path) -> "IOCMatcher":
        def load(name):
            f = d / name
            return {l.strip().lower() for l in f.read_text().splitlines()
                    if l.strip() and not l.startswith("#")} if f.exists() else set()
        return cls(load("mercenary_domains.txt"), load("mercenary_procnames.txt"))

    def match_domain(self, host: str) -> bool:
        h = (host or "").lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def match_proc(self, name: str) -> bool:
        n = (name or "").lower()
        return n in self.procnames or n.removesuffix(".exe") in self.procnames
