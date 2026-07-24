"""Native autostart collector -- the shipped-default replacement for the bundled
Sysinternals ``autorunsc``.

Why this exists: ``autorunsc64.exe`` may NOT be redistributed (Sysinternals license:
no "publish the software for others to copy", no free-use exception), so a public
spyscan build cannot bundle it. This collector reimplements the *high-value* autostart
(ASEP) categories in pure Python + built-in Windows facilities, with no external binary:

  * Registry Run / RunOnce (+ legacy RunServices) keys, HKLM (native + WOW64
    32-bit views) and HKCU (native only -- HKCU\\SOFTWARE is shared, not
    redirected, so a second view would only duplicate)       -- T1547.001
  * Startup folders (per-user + common)                      -- T1547.001
  * Winlogon Shell / Userinit (a classic logon hijack)       -- T1547.004
  * WMI permanent event subscriptions (fileless persistence) -- T1546.003

It is deliberately a SUBSET of what ``autorunsc -a *`` sweeps (63 populated locations on
the Windows 11 box this was measured on; this collector reaches 6 of them). The gap
is documented in the README. If a user installs their own autorunsc, the ``autoruns``
collector runs the fuller sweep and THIS collector steps aside (see ``gather``) so the
same autostart is never reported twice.

Signing: the native path cannot cheaply Authenticode-verify, so every fact leaves the
signing signals UNKNOWN (``verified``/``signed`` = None, never False). The pipeline's
scoped enrichment pass then runs a real Authenticode check on the suspicious ones,
exactly as it does for autorunsc-sourced facts -- so unknown is never mis-scored as
unsigned (see enrich/signature.py + score.py's ``verified is False`` guard).

Shape parity: facts are ``kind="autostart"`` with the same attrs autoruns emits, so they
flow through the existing persistence/scoring rules unchanged.
"""
from __future__ import annotations
import csv, io, os, subprocess
from spyscan.facts import Fact, make_key
from spyscan.collectors.base import Collector, ScanContext, is_tempish
from spyscan.collectors.autoruns import autorunsc_available

name = "autostart_native"

RUN_ATTACK = "T1547.001"        # Boot or Logon Autostart Execution: Registry Run / Startup folder
WINLOGON_ATTACK = "T1547.004"   # Boot or Logon Autostart Execution: Winlogon Helper DLL
WMI_ATTACK = "T1546.003"        # Event Triggered Execution: WMI Event Subscription

# Registry autostart value-keys swept under both HKLM and HKCU. RunServices* are 9x-era
# legacy; whether current Windows still executes them is NOT verified here, but they cost
# one key open each and a value sitting there is worth surfacing either way.
_RUN_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
)
_WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_WINLOGON_VALUES = ("Shell", "Userinit")

# Which registry views to sweep per hive -- NOT both views for both hives.
#
#   HKLM\SOFTWARE is REDIRECTED under WOW64: a 32-bit implant's Run value lives in a
#   physically separate Wow6432Node key that the native view cannot see, so HKLM genuinely
#   needs both passes.
#   HKCU\SOFTWARE is SHARED, not redirected -- one physical key mapped into both logical
#   views. A second HKCU pass therefore re-reads the SAME values and (because the view name
#   lands in `location`, and `location` feeds entity_key) mints a DUPLICATE fact for every
#   user autostart. Native only there.
#
# Source: "Registry Keys Affected by WOW64" -- HKEY_CURRENT_USER and HKEY_CURRENT_USER\
# SOFTWARE are both listed Shared, and "subkeys ... inherit the parent key's behavior
# unless otherwise specified" (only HKCU\SOFTWARE\Classes and below are redirected).
# https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys
_VIEWS_BY_SCOPE = {"HKLM": ("native", "wow64"), "HKCU": ("native",)}


# --------------------------------------------------------------------------- helpers

def _exe_from_command(cmd: str) -> str:
    """Best-effort image path out of a launch command.

    ``"C:\\Program Files\\App\\a.exe" -x`` -> ``C:\\Program Files\\App\\a.exe``
    ``C:\\Windows\\system32\\userinit.exe,`` -> ``C:\\Windows\\system32\\userinit.exe``
    ``rundll32.exe foo,Bar``                 -> ``rundll32.exe``
    Returns "" for an empty command. Never raises.
    """
    c = (cmd or "").strip()
    if not c:
        return ""
    if c[0] == '"':
        end = c.find('"', 1)
        return c[1:end] if end > 0 else c[1:]
    low = c.lower()
    idx = low.find(".exe")
    if idx != -1:
        return c[:idx + 4]
    parts = c.split()
    return parts[0] if parts else c


# --------------------------------------------------------------------------- gather (impure)

def _gather_run() -> list[tuple]:
    """(scope, view, key_path, value_name, value_data) for every Run-key value."""
    import winreg
    rows: list[tuple] = []
    hives = ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU"))
    # 32-bit (WOW64) view only where the hive is actually redirected -- see _VIEWS_BY_SCOPE.
    access_for = {"native": winreg.KEY_READ,
                  "wow64": winreg.KEY_READ | winreg.KEY_WOW64_32KEY}
    for hive, scope in hives:
        for key_path in _RUN_KEYS:
            for view in _VIEWS_BY_SCOPE[scope]:
                access = access_for[view]
                try:
                    k = winreg.OpenKey(hive, key_path, 0, access)
                except OSError:
                    continue
                try:
                    i = 0
                    while True:
                        try:
                            vname, vdata, _ = winreg.EnumValue(k, i)
                            i += 1
                        except OSError:
                            break
                        rows.append((scope, view, key_path, vname, str(vdata)))
                finally:
                    winreg.CloseKey(k)
    return rows


def _gather_winlogon() -> list[tuple]:
    """(scope, value_name, value_data) for Winlogon Shell/Userinit, HKLM + HKCU."""
    import winreg
    rows: list[tuple] = []
    for hive, scope in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        try:
            k = winreg.OpenKey(hive, _WINLOGON_KEY, 0, winreg.KEY_READ)
        except OSError:
            continue
        try:
            for val in _WINLOGON_VALUES:
                try:
                    data, _ = winreg.QueryValueEx(k, val)
                except OSError:
                    continue
                rows.append((scope, val, str(data)))
        finally:
            winreg.CloseKey(k)
    return rows


def _startup_dirs() -> list[tuple]:
    """(scope, folder_path) for the per-user and common Startup folders."""
    dirs = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("ProgramData")
    sub = r"Microsoft\Windows\Start Menu\Programs\Startup"
    if appdata:
        dirs.append(("user", os.path.join(appdata, sub)))
    if programdata:
        dirs.append(("common", os.path.join(programdata, sub)))
    return dirs


def _lnk_targets(paths: list[str]) -> dict[str, tuple[str, str]]:
    """fullpath -> (target, arguments) for the .lnk files among ``paths``.

    Resolved in one WScript.Shell PowerShell call (no per-file process spawn).
    Empty dict on any failure -- facts then fall back to the .lnk path itself,
    which degrades to a missing signal, never a false one.
    """
    lnks = [p for p in paths if p.lower().endswith(".lnk")]
    if not lnks:
        return {}
    lst = ",".join("'" + p.replace("'", "''") + "'" for p in lnks)
    out = _ps_csv(
        "$sh = New-Object -ComObject WScript.Shell; "
        f"@({lst}) | ForEach-Object {{ $s = $sh.CreateShortcut($_); "
        "[pscustomobject]@{Path=$_; Target=$s.TargetPath; Args=$s.Arguments} } | "
        "ConvertTo-Csv -NoTypeInformation")
    m: dict[str, tuple[str, str]] = {}
    for row in _reader(out):
        p = (row.get("Path") or "").strip()
        if p:
            m[p] = ((row.get("Target") or "").strip(),
                    (row.get("Args") or "").strip())
    return m


def _gather_startup() -> list[tuple]:
    """(scope, folder, filename, fullpath, target, target_args) per Startup entry.

    ``target`` is the resolved .lnk target ('' for non-lnk files or a failed
    resolution): the PROGRAM the entry runs is the entity the fact must describe;
    the .lnk container file is location detail (ADR 0002 rule 4)."""
    entries: list[tuple] = []
    for scope, folder in _startup_dirs():
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for fn in names:
            if fn.lower() == "desktop.ini":
                continue
            entries.append((scope, folder, fn, os.path.join(folder, fn)))
    targets = _lnk_targets([e[3] for e in entries])
    return [(scope, folder, fn, fp, *targets.get(fp, ("", "")))
            for scope, folder, fn, fp in entries]


def _ps_csv(ps_expr: str) -> bytes:
    """Run a PowerShell pipeline ending in ConvertTo-Csv; bytes, empty on any failure."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_expr],
            capture_output=True, timeout=60)
        return out.stdout
    except Exception:
        return b""


def _gather_wmi() -> dict:
    """WMI permanent event consumers (root/subscription). Fileless persistence."""
    cmdline = _ps_csv(
        "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer "
        "-ErrorAction SilentlyContinue | "
        "Select-Object Name,ExecutablePath,CommandLineTemplate | ConvertTo-Csv -NoTypeInformation")
    script = _ps_csv(
        "Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer "
        "-ErrorAction SilentlyContinue | "
        "Select-Object Name,ScriptingEngine,ScriptFileName | ConvertTo-Csv -NoTypeInformation")
    return {"cmdline": cmdline, "script": script}


def gather() -> dict:                            # impure edge (integration-tested)
    # Step aside when a user-provided autorunsc is available: the `autoruns` collector
    # then runs the fuller `-a *` sweep and would double-report these same
    # autostarts. Native is the fallback for the (default) no-autorunsc build.
    if autorunsc_available():
        return {}
    out: dict = {}
    for key, fn in (("run", _gather_run), ("winlogon", _gather_winlogon),
                    ("startup", _gather_startup), ("wmi", _gather_wmi)):
        try:
            out[key] = fn()
        except Exception:
            out[key] = [] if key != "wmi" else {}
    return out


# --------------------------------------------------------------------------- parse (pure)

def _mk(location: str, entry: str, image_path: str, launch: str, attack: str,
        extra: dict | None = None) -> Fact:
    a = {
        "entry": entry,
        "location": location,
        "image_path": image_path,
        "launch_string": launch,
        "company": "",
        "signer": "",
        # UNKNOWN, not unsigned: None avoids score.py's `verified is False` penalty; the
        # pipeline enrich pass runs the real Authenticode check on suspicious candidates.
        "verified": None,
        "signed": None,
        "trusted_ms": False,
        "sha256": "",
        "md5": "",
        "enabled": True,
        "from_temp": is_tempish(image_path) or is_tempish(launch),
        "source": "native",   # provenance: separates these from autorunsc-sourced facts
    }
    if extra:
        a.update(extra)
    return Fact(collector=name, entity_key=make_key(name, location, entry, image_path),
                kind="autostart", label=f"{entry} ({image_path})", attack_id=attack, attrs=a)


def _parse_run(rows: list[tuple]) -> list[Fact]:
    facts = []
    for scope, view, key_path, vname, vdata in rows:
        loc = f"{scope}\\{key_path}" + (" (WOW64)" if view == "wow64" else "")
        facts.append(_mk(loc, vname, _exe_from_command(vdata), vdata, RUN_ATTACK))
    return facts


def _parse_winlogon(rows: list[tuple]) -> list[Fact]:
    # A Winlogon Shell/Userinit value is a comma-separated PROGRAM LIST; the classic
    # T1547.004 hijack APPENDS a payload ("userinit.exe,implant.exe"). One value is
    # therefore N entities (ADR 0002 rule 2: split) -- each component gets its own
    # image_path and entity_key, so an appended payload mints a NEW fact (+3 new,
    # its own from_temp/allowlist semantics) instead of collapsing into an
    # attrs-only 'changed' on the stock binary's fact.
    facts = []
    for scope, val, data in rows:
        loc = f"{scope}\\{_WINLOGON_KEY}"
        comps = [c.strip() for c in str(data).split(",") if c.strip()]
        by_image: dict[str, list[str]] = {}
        for c in comps:
            by_image.setdefault(_exe_from_command(c), []).append(c)
        for img, group in by_image.items():
            facts.append(_mk(loc, val, img, "; ".join(sorted(group)), WINLOGON_ATTACK))
    return facts


def _parse_startup(rows: list[tuple]) -> list[Fact]:
    facts = []
    for scope, folder, fn, fullpath, target, targs in rows:
        loc = f"Startup folder ({scope}): {folder}"
        img = target or fullpath
        launch = f"{target} {targs}".strip() if target else fullpath
        # from_temp is judged on the TARGET the entry runs -- but a path inside the
        # startup folder itself is exempt: every per-user entry lives under
        # AppData\Roaming by construction, and a 100%-firing signal is no signal.
        in_container = os.path.dirname(img).lower() == folder.lower()
        from_temp = (is_tempish(img) or is_tempish(launch)) and not in_container
        facts.append(_mk(loc, fn, img, launch, RUN_ATTACK,
                         {"from_temp": from_temp,
                          "shortcut": fullpath if target else ""}))
    return facts


def _reader(raw: bytes):
    if not raw:
        return iter(())
    return csv.DictReader(io.StringIO(raw.decode("utf-8-sig", errors="replace")))


def _parse_wmi(raw: dict) -> list[Fact]:
    facts = []
    for row in _reader((raw or {}).get("cmdline", b"")):
        n = (row.get("Name") or "").strip()
        if not n:
            continue
        cmd = (row.get("CommandLineTemplate") or "").strip()
        img = (row.get("ExecutablePath") or "").strip() or _exe_from_command(cmd)
        facts.append(_mk("WMI: root/subscription CommandLineEventConsumer", n, img, cmd,
                         WMI_ATTACK, {"wmi_class": "CommandLineEventConsumer"}))
    for row in _reader((raw or {}).get("script", b"")):
        n = (row.get("Name") or "").strip()
        if not n:
            continue
        engine = (row.get("ScriptingEngine") or "").strip()
        sfile = (row.get("ScriptFileName") or "").strip()
        facts.append(_mk("WMI: root/subscription ActiveScriptEventConsumer", n, sfile,
                         f"{engine}: {sfile}".strip(": "), WMI_ATTACK,
                         {"wmi_class": "ActiveScriptEventConsumer", "scripting_engine": engine}))
    return facts


def parse(raw: dict) -> list[Fact]:              # PURE
    raw = raw or {}
    return (_parse_run(raw.get("run", []))
            + _parse_winlogon(raw.get("winlogon", []))
            + _parse_startup(raw.get("startup", []))
            + _parse_wmi(raw.get("wmi", {})))


class AutostartNativeCollector(Collector):
    """Native autostart (registry Run keys, Startup folders, Winlogon, WMI subs).

    The shipped default in place of the non-redistributable Sysinternals autorunsc;
    steps aside when a user-installed autorunsc is present. No config -> ignores ctx.
    """
    name = "autostart_native"

    def gather(self, ctx: ScanContext) -> dict:
        return gather()

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
