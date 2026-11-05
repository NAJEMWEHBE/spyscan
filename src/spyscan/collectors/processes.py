from __future__ import annotations
import psutil
from spyscan.facts import Fact, make_key
from spyscan.collectors.base import Collector, ScanContext, is_tempish

name = "processes"

def gather() -> list[dict]:
    out = []
    for p in psutil.process_iter(["pid", "name", "exe", "ppid", "cmdline"]):
        try:
            i = p.info
            parent = psutil.Process(i["ppid"]).name() if i.get("ppid") else ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            parent = ""
        out.append({"pid": i.get("pid"), "name": i.get("name") or "",
                    "exe": i.get("exe") or "", "ppid": i.get("ppid"),
                    "pname": parent, "cmdline": i.get("cmdline") or []})
    return out

def _is_windowstyle(tok: str) -> bool:
    """-w / -wi / -win ... / -windowstyle (PowerShell accepts any unique prefix)."""
    t = tok.lower().lstrip("-/")
    return tok[:1] in "-/" and len(t) >= 1 and "windowstyle".startswith(t)


def hidden_window(cmdline: list[str]) -> bool:
    """True for a hidden-window launch: '-WindowStyle Hidden', '-w hidden',
    '-windowstyle:hidden', or a bare '-hidden' (audit #11: only the last one,
    which PowerShell does not even have, used to count)."""
    toks = [str(t) for t in (cmdline or [])]
    for i, tok in enumerate(toks):
        low = tok.lower()
        if low == "-hidden":
            return True
        flag, sep, val = low.partition(":")
        if _is_windowstyle(flag if sep else low):
            nxt = val if sep else (toks[i + 1].lower() if i + 1 < len(toks) else "")
            if nxt in ("hidden", "1"):
                return True
    return False


_ENC_FLAGS = {"-e", "-ec", "-en", "-enc", "-enco", "-encod", "-encode", "-encoded",
              "-encodedc", "-encodedco", "-encodedcom", "-encodedcomm",
              "-encodedcomma", "-encodedcomman", "-encodedcommand"}


def encoded_command(cmdline: list[str]) -> bool:
    """True when PowerShell is handed a base64 -EncodedCommand (-enc / -e / -ec)."""
    return any(str(t).lower() in _ENC_FLAGS for t in (cmdline or [])[1:])


def parse(snaps: list[dict]) -> list[Fact]:
    # Fold: one Fact per (process name, full exe path) entity (ADR 0002 rule 2).
    # 81 svchost.exe instances are one real-world entity; a same-named implant at a
    # DIFFERENT path gets its own key and therefore surfaces as 'added'.
    groups: dict[tuple[str, str], list[dict]] = {}
    for s in snaps:
        groups.setdefault((s.get("name") or "", (s.get("exe") or "").lower()),
                          []).append(s)

    facts = []
    for (pname, exe_low), rows in groups.items():
        exe = min(r.get("exe") or "" for r in rows)  # deterministic case pick
        pids = sorted(r.get("pid") for r in rows if r.get("pid") is not None)
        n = len(rows)
        label = (f"{pname} (pid {pids[0]})" if n == 1 and pids
                 else f"{pname} ({n} instances)")
        attrs = {
            "exe": exe,
            "from_temp": is_tempish(exe),
            "hidden_flag": any(hidden_window(r.get("cmdline") or []) for r in rows),
        }
        # set only when true: a new always-present key would make every process
        # in an existing baseline diff as 'changed' (ADR 0002)
        if any(encoded_command(r.get("cmdline") or []) for r in rows):
            attrs["encoded_flag"] = True
        facts.append(Fact(
            collector=name,
            # empty exe (access denied / kernel) is a sentinel, never identity data
            entity_key=make_key(name, pname, exe_low or "(unknown-path)"),
            kind="process",
            label=label,
            attack_id=None,
            attrs=attrs,
            # volatile per-instance observations: never diffed (ADR 0002 rule 3)
            observed={
                "pids": pids,
                "instance_count": n,
                "parents": sorted({r.get("pname", "") for r in rows}),
                "cmdlines": sorted({" ".join(r.get("cmdline") or []) for r in rows}),
            },
        ))
    return facts


class ProcessesCollector(Collector):
    """Running processes (psutil). No config needed -> ignores ctx."""
    name = "processes"

    def gather(self, ctx: ScanContext) -> list[dict]:
        return gather()

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
