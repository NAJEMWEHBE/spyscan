from __future__ import annotations
import csv, io, subprocess
from spyscan.facts import Fact, make_key
from spyscan.collectors.base import Collector, ScanContext, is_tempish

name = "drivers"
ATTACK = "T1014"            # Rootkit (kernel driver implant); also relates to T1543.003

# Real header captured on the box (driverquery /fo csv /v):
#   Module Name,Display Name,Description,Driver Type,Start Mode,State,Status,
#   Accept Stop,Accept Pause,Paged Pool(bytes),Code(bytes),BSS(bytes),Link Date,Path,Init(bytes)

def gather() -> bytes:                       # impure edge (integration-tested)
    try:
        out = subprocess.run(
            ["driverquery", "/fo", "csv", "/v"],
            capture_output=True, timeout=60)
        return out.stdout
    except Exception:
        return b""

def parse(raw: bytes) -> list[Fact]:         # PURE
    if not raw:
        return []
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    facts = []
    for row in reader:
        module = (row.get("Module Name") or "").strip()
        if not module or module == "Module Name":
            continue
        path = (row.get("Path") or "").strip()
        facts.append(Fact(
            collector=name,
            # Module Name IS the driver's stable identity (its SCM service name).
            # The path must stay OUT of the key: DriverStore updates move the .sys
            # to a new versioned hash dir, and a path-bearing key turns every
            # routine driver update into a phantom added + "possible implant
            # cleanup" removed pair (ADR 0002 rule 1). A real relocation now
            # surfaces as 'changed' on the stable key via the path attr.
            entity_key=make_key(name, module),
            kind="driver",
            label=f"driver: {row.get('Display Name','').strip() or module}",
            attack_id=ATTACK,
            attrs={
                "module": module,
                "display_name": (row.get("Display Name") or "").strip(),
                "driver_type": (row.get("Driver Type") or "").strip(),
                "start_mode": (row.get("Start Mode") or "").strip(),
                "link_date": (row.get("Link Date") or "").strip(),
                "path": path,
                "from_temp": is_tempish(path),
            },
            # runtime scheduler/PnP state, not a property of the installed driver:
            # 349/466 drivers on the reference box are Manual-start and flip
            # Running<->Stopped on demand (ADR 0002 rule 3)
            observed={
                "state": (row.get("State") or "").strip(),
                "status": (row.get("Status") or "").strip(),
            },
        ))
    return facts


class DriversCollector(Collector):
    """Kernel drivers (driverquery). No config needed -> ignores ctx."""
    name = "drivers"

    def gather(self, ctx: ScanContext) -> bytes:
        return gather()

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
