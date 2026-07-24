# src/spyscan/canary_audit.py
"""Best-effort Windows access auditing for canary files (WHO touched a decoy).

If the Security event log is recording object-access (Event ID 4663) for the
canary paths, we can attribute a trip to a concrete PROCESS -- "Temp\\stealer.exe
read passwords.txt at 08:15". That is the strongest possible evidence.

But this requires TWO things that are usually OFF:
  1. The "Audit File System" subcategory enabled (auditpol), AND
  2. a SACL on each canary file telling Windows to audit access (Set-Acl/icacls),
and reading the Security log needs admin. So this layer DEGRADES GRACEFULLY:

  * ``read_access_events`` is a PURE parser over event XML/text (unit-tested with
    a fixture) -- no system calls, fully deterministic.
  * ``gather`` is the live, best-effort wrapper: it shells out to wevtutil via an
    injectable ``runner`` and returns [] on ANY failure (no admin, no SACL, log
    cleared, tool missing). It never raises and never crashes the scan.

Without admin + SACL the canary still works -- it falls back to the
hash/mtime/size/missing detection in ``canary.check`` (still strong; that catches
any MODIFY/COPY-with-touch/DELETE). This module only ADDS attribution when the OS
happens to be auditing. ``enable_audit_commands`` prints the exact admin commands
the user can run to turn real per-access attribution on (it does NOT elevate).

LOCAL-ONLY: everything reads the on-box Security log; nothing leaves the machine.
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET

EVENT_ID = 4663


def _harden_xml(xml_text: str) -> str:
    """Neutralise XXE + billion-laughs BEFORE parsing with stdlib ElementTree.

    We do not pull in defusedxml (the app stays dependency-light + standalone),
    so we instead strip the only constructs those attacks need: any DOCTYPE and
    ENTITY declarations. Without a DOCTYPE there are no custom entities to expand
    (no entity bomb) and no external/system entities to resolve (no XXE / SSRF /
    local-file read). The Security log never legitimately contains a DOCTYPE, so
    this is lossless for our real input. (Defence-in-depth: this parser only ever
    reads the LOCAL Security log, but an implant could craft event text, so we
    harden anyway.)
    """
    # strip a DOCTYPE incl. any internal subset [...] (which can contain '>'),
    # then any stray ENTITY decls, then any leftover entity REFERENCES (&name;)
    # other than the five XML built-ins. Removing the references means a crafted
    # event still parses (we don't crash on an undefined entity) but no entity is
    # ever expanded -- no file read, no exponential blow-up.
    xml_text = re.sub(r"<!DOCTYPE\b.*?(\[.*?\])?\s*>", "", xml_text,
                      flags=re.IGNORECASE | re.DOTALL)
    xml_text = re.sub(r"<!ENTITY\b.*?>", "", xml_text,
                      flags=re.IGNORECASE | re.DOTALL)
    xml_text = re.sub(r"&(?!(amp|lt|gt|quot|apos);)\w+;", "", xml_text,
                      flags=re.IGNORECASE)
    return xml_text


def _strip_ns(xml_text: str) -> str:
    """Drop XML namespaces so ElementTree queries are simple/robust, after
    hardening away DOCTYPE/ENTITY (XXE + billion-laughs) constructs.

    The Security-log <Event> uses a default namespace; stripping it lets us find
    plain ``EventData/Data`` without carrying the namespace URI everywhere.
    """
    xml_text = _harden_xml(xml_text)
    # remove xmlns="..." declarations and any ns: prefixes on tags
    xml_text = re.sub(r'\sxmlns(:\w+)?="[^"]*"', "", xml_text)
    xml_text = re.sub(r"<(/?)\w+:", r"<\1", xml_text)
    return xml_text


def _event_to_record(ev: ET.Element) -> dict | None:
    """Map one <Event> element to a flat dict, or None if it isn't a 4663."""
    sys_el = ev.find("System")
    eid_el = sys_el.find("EventID") if sys_el is not None else None
    try:
        eid = int((eid_el.text or "").strip()) if eid_el is not None else None
    except ValueError:
        eid = None
    if eid != EVENT_ID:
        return None

    data: dict[str, str] = {}
    edata = ev.find("EventData")
    if edata is not None:
        for d in edata.findall("Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()

    tc = sys_el.find("TimeCreated") if sys_el is not None else None
    when = tc.get("SystemTime") if tc is not None else ""

    return {
        "event_id": EVENT_ID,
        "time": when,
        "object_name": data.get("ObjectName", ""),
        "process_name": data.get("ProcessName", ""),
        "process_id": data.get("ProcessId", ""),
        "access_mask": data.get("AccessMask", ""),
        "subject_user": data.get("SubjectUserName", ""),
    }


def read_access_events(paths, since=None, runner=None) -> list[dict]:
    """PURE parser: extract 4663 object-access events for the given canary paths.

    Args:
      paths:  canary file paths to keep (case-insensitive exact match on
              ObjectName). Empty -> [].
      since:  accepted for signature symmetry with the live gather; the parser
              itself does not filter by time (the query does that upstream).
      runner: callable(...)->str returning the raw event XML/text. Injected so
              this function is pure + unit-testable; in production ``gather``
              supplies a real wevtutil runner.

    Returns a list of flat event dicts. Non-XML / error output -> [] (never raises).
    """
    if not paths or runner is None:
        return []
    wanted = {str(p).strip().lower() for p in paths if str(p).strip()}
    if not wanted:
        return []

    try:
        raw = runner(list(paths), since)
    except Exception:
        return []
    if not raw or "<Event" not in raw:
        return []

    try:
        root = ET.fromstring("<Events>" + _wrap_inner(_strip_ns(raw)) + "</Events>")
    except ET.ParseError:
        return []

    out: list[dict] = []
    for ev in root.iter("Event"):
        rec = _event_to_record(ev)
        if rec is None:
            continue
        if rec["object_name"].strip().lower() in wanted:
            out.append(rec)
    return out


def _wrap_inner(xml_text: str) -> str:
    """Return the inner <Event>...</Event> sequence regardless of whether the
    runner already wrapped them in <Events> (wevtutil) or not (single events)."""
    m = re.search(r"<Events>(.*)</Events>", xml_text, re.DOTALL)
    if m:
        return m.group(1)
    # strip any XML declaration so our outer <Events> wrapper parses
    return re.sub(r"<\?xml[^>]*\?>", "", xml_text)


def _wevtutil_runner(paths, since) -> str:
    """Live runner: query the Security log for 4663 events via wevtutil.

    Best-effort: returns "" on any failure (no admin, tool missing). The caller
    (gather) treats "" as 'no attribution available' and falls back to the
    hash/mtime/size detection. Never raises out of here.
    """
    import subprocess
    # XPath: object-access events; we over-fetch then filter by path in the parser
    # (keeping the query simple + robust across locales). /e:Events wraps output.
    query = f"*[System[(EventID={EVENT_ID})]]"
    cmd = ["wevtutil", "qe", "Security", "/q:" + query,
           "/f:RenderedXml", "/c:200", "/rd:true", "/e:Events"]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception:
        return ""
    if cp.returncode != 0:
        return ""
    return cp.stdout or ""


def gather(paths, since=None, runner=None) -> list[dict]:
    """Live best-effort attribution. Returns [] when auditing/admin is
    unavailable -- never raises, never crashes the scan."""
    if not paths:
        return []
    runner = runner if runner is not None else _wevtutil_runner
    try:
        return read_access_events(paths, since=since, runner=runner)
    except Exception:
        return []


def enable_audit_commands(paths) -> str:
    """Return (do NOT run) the exact admin commands that turn on real per-access
    attribution for the given canary files. Pure string builder -- never elevates.
    """
    lines = [
        "# Run these in an ELEVATED PowerShell (Admin) to enable per-access",
        "# attribution for canary files. spyscan will NOT do this for you.",
        "",
        "# 1) Turn on File System object-access auditing (success+failure):",
        'auditpol /set /subcategory:"File System" /success:enable /failure:enable',
        "",
        "# 2) Add an audit SACL to each canary so Windows logs reads/writes:",
    ]
    for p in paths:
        lines.append(
            "$acl = Get-Acl -Path '" + str(p) + "';")
        lines.append(
            "$rule = New-Object System.Security.AccessControl.FileSystemAuditRule("
            "'Everyone','ReadData,WriteData,Delete','Success');")
        lines.append("$acl.AddAuditRule($rule);")
        lines.append("Set-Acl -Path '" + str(p) + "' -AclObject $acl;")
        lines.append("")
    lines.append("# (icacls can also set audit ACEs; Set-Acl shown for clarity.)")
    lines.append("# After this, a canary read/modify shows up as Event ID 4663 with")
    lines.append("# the snooping process name -- spyscan surfaces it automatically.")
    return "\n".join(lines)
