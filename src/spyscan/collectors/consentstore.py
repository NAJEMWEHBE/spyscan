from __future__ import annotations
from spyscan.facts import Fact, make_key
from spyscan.collectors.base import Collector, ScanContext

name = "consentstore"
_ATTACK = {"webcam": "T1125", "microphone": "T1123"}
_NONPACKAGED = "NonPackaged"


def _subkeys(winreg, key):
    i = 0
    while True:
        try:
            yield winreg.EnumKey(key, i)
            i += 1
        except OSError:
            return


def gather() -> list[tuple]:                 # impure: walk registry
    import winreg
    rows = []
    bases = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    root = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"

    def add(scope, cap, app_id):
        try:
            ak = winreg.OpenKey(hive, f"{root}\\{cap}\\{app_id}")
        except OSError:
            return
        rows.append((scope, cap, app_id,
                     _rd(winreg, ak, "LastUsedTimeStart"),
                     _rd(winreg, ak, "LastUsedTimeStop")))

    for hive, scope in bases:
        for cap in ("webcam", "microphone"):
            try:
                k = winreg.OpenKey(hive, root + "\\" + cap)
            except OSError:
                continue
            for app in _subkeys(winreg, k):
                if app == _NONPACKAGED:
                    # Container, not an app (ADR 0002 rule 2): its children are the
                    # classic Win32 apps ('#'-encoded exe paths) -- the population
                    # the webcam/mic feature exists to watch. Enumerate them; never
                    # emit the container itself.
                    try:
                        nk = winreg.OpenKey(hive, f"{root}\\{cap}\\{app}")
                    except OSError:
                        continue
                    for child in _subkeys(winreg, nk):
                        add(scope, cap, f"{app}\\{child}")
                else:
                    add(scope, cap, app)
    return rows


def _rd(winreg, key, val):
    try:
        return winreg.QueryValueEx(key, val)[0]
    except OSError:
        return None


def parse(rows: list[tuple]) -> list[Fact]:
    facts = []
    for scope, cap, app_id, start, stop in rows:
        container, _, leaf = app_id.partition("\\")
        if leaf:                     # NonPackaged\<raw>: '#'-encoded Win32 exe path
            app_name = leaf.replace("#", "\\")
            key_parts = (cap, scope, container, app_name)
            packaged = False
        else:                        # Store package id, used verbatim
            app_name = app_id
            key_parts = (cap, scope, app_name)
            packaged = True
        facts.append(Fact(
            collector=name,
            # HKCU and HKLM ConsentStore entries are distinct registry records, so
            # scope is identity (ADR 0002 rule 1) -- without it they collide.
            entity_key=make_key(name, *key_parts),
            kind="device_use",
            label=f"{cap}: {app_name}",
            attack_id=_ATTACK.get(cap),
            attrs={"scope": scope, "capability": cap, "app": app_name,
                   "packaged": packaged,
                   "last_start": start, "last_stop": stop,
                   "in_use_now": stop == 0},
        ))
    return facts


class ConsentStoreCollector(Collector):
    """Webcam/mic ConsentStore usage (registry). No config -> ignores ctx."""
    name = "consentstore"

    def gather(self, ctx: ScanContext) -> list[tuple]:
        return gather()

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
