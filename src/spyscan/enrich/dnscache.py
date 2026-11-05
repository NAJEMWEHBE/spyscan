"""The Windows DNS client cache: which names this PC resolved, and to which IPs.

Audit #13: connection facts carry remote IPs, so the domain IOC list could
never match them. The cache maps an IP back to every name in its lookup chain
(the queried name, any CNAME hops, the final host), and its names on their own
show a lookup of a listed domain even when no connection is open any more.

``parse`` is pure; ``gather`` reads the live cache through the data-safe
PowerShell adapter and returns an empty cache on any failure.
"""
from __future__ import annotations
import csv
import io
import ipaddress
from dataclasses import dataclass, field

from spyscan import powershell

# Constant text: no data is interpolated into it.
SCRIPT = "Get-DnsClientCache | Select-Object Entry,Name,Data | ConvertTo-Csv -NoTypeInformation"


@dataclass(frozen=True)
class DnsCache:
    by_ip: dict[str, frozenset[str]] = field(default_factory=dict)
    names: frozenset[str] = frozenset()


def _ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def parse(raw: bytes) -> DnsCache:
    """PURE: ConvertTo-Csv output of Entry,Name,Data -> DnsCache."""
    if not raw:
        return DnsCache()
    text = raw.decode("utf-8-sig", errors="replace")
    by_ip: dict[str, set[str]] = {}
    names: set[str] = set()
    for row in csv.DictReader(io.StringIO(text)):
        chain = {n for k in ("Entry", "Name")
                 if (n := (row.get(k) or "").strip().lower().rstrip("."))}
        data = (row.get("Data") or "").strip()
        ip = _ip(data)
        if ip:
            by_ip.setdefault(ip, set()).update(chain)
        elif data:
            chain.add(data.lower().rstrip("."))        # a CNAME target
        names |= chain
    return DnsCache({ip: frozenset(n) for ip, n in by_ip.items()}, frozenset(names))


def gather() -> DnsCache:                    # impure edge
    try:
        return parse(powershell.run(SCRIPT, timeout=30))
    except Exception:
        return DnsCache()
