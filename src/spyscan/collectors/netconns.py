from __future__ import annotations
import psutil
from spyscan.facts import Fact, make_key
from spyscan.collectors.base import Collector, ScanContext

name = "netconns"


def gather() -> list[dict]:
    out = []
    for c in psutil.net_connections(kind="inet"):
        # Unattributed TIME_WAIT is a dead socket whose owner already exited --
        # not live communication. Keeping them mints hundreds of ownerless keys
        # that churn as CDN IPs rotate (ADR 0002; grilled 2026-07-24).
        if not c.pid and c.status == psutil.CONN_TIME_WAIT:
            continue
        try:
            pname = psutil.Process(c.pid).name() if c.pid else ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pname = ""
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        out.append({"pid": c.pid, "laddr": laddr, "raddr": raddr,
                    "status": c.status, "pname": pname})
    return out


def _owner(s: dict) -> str:
    """Stable owner name for a socket row -- explicit sentinels, never '' as data
    (ADR 0002 rule 4): kernel/no-owner -> '(unowned)'; a live pid whose name we
    could not read (AccessDenied) -> '(unresolved)'."""
    if s.get("pname"):
        return s["pname"]
    return "(unresolved)" if s.get("pid") else "(unowned)"


def parse(snaps: list[dict]) -> list[Fact]:
    # Fold: one Fact per (owner process, endpoint) entity (ADR 0002 rule 2). The
    # endpoint is the remote addr for outbound sockets, the local addr for
    # listeners -- 91 concurrent sockets to one endpoint are one relationship.
    groups: dict[tuple[str, str, bool], list[dict]] = {}
    for s in snaps:
        endpoint = s.get("raddr") or s.get("laddr") or ""
        groups.setdefault((_owner(s), endpoint, not s.get("raddr")), []).append(s)

    facts = []
    for (pname, endpoint, listening), rows in groups.items():
        raddr = rows[0].get("raddr") or ""
        rip, _, rport = raddr.rpartition(":")
        n = len(rows)
        suffix = f" (x{n})" if n > 1 else ""
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, pname,
                                ("listen " + endpoint) if listening else endpoint),
            kind="connection",
            label=f"{pname} -> {raddr if raddr else '(listen) ' + endpoint}{suffix}",
            attack_id="T1071" if raddr else None,
            attrs={"process": pname,
                   "remote_ip": rip,
                   "remote_port": int(rport) if rport.isdigit() else None,
                   "listening": listening},
            # per-socket volatile data: never diffed (ADR 0002 rule 3)
            observed={
                "conn_count": n,
                "pids": sorted({r.get("pid") for r in rows if r.get("pid")}),
                "locals": sorted({r.get("laddr", "") for r in rows}),
                "statuses": sorted({r.get("status") or "" for r in rows}),
            },
        ))
    return facts


class NetconnsCollector(Collector):
    """Live TCP/UDP connections (psutil). No config needed -> ignores ctx."""
    name = "netconns"

    def gather(self, ctx: ScanContext) -> list[dict]:
        return gather()

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
