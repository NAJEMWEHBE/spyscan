from __future__ import annotations
import csv, io, subprocess
from spyscan.facts import Fact, make_key
from spyscan.collectors.base import Collector, ScanContext, is_tempish

name = "services_tasks"
SERVICE_ATTACK = "T1543.003"        # Create or Modify System Process: Windows Service
TASK_ATTACK = "T1053.005"           # Scheduled Task/Job: Scheduled Task

# Real headers captured on the box:
#   Win32_Service | ConvertTo-Csv : Name,DisplayName,PathName,StartMode,State,StartName,ServiceType
#   schtasks /query /fo csv /v     : HostName,TaskName,...,Task To Run,...,Run As User,Author,Status,...

def _ps_csv(ps_expr: str) -> bytes:
    """Run a PowerShell pipeline that ends in ConvertTo-Csv, return its bytes."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_expr],
            capture_output=True, timeout=60)
        return out.stdout
    except Exception:
        return b""

def gather() -> dict:                        # impure edge (integration-tested)
    services = _ps_csv(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,PathName,StartMode,State,StartName,ServiceType | "
        "ConvertTo-Csv -NoTypeInformation")
    try:
        tasks = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True, timeout=60).stdout
    except Exception:
        tasks = b""
    return {"services": services, "tasks": tasks}

def _reader(raw: bytes):
    if not raw:
        return iter(())
    text = raw.decode("utf-8-sig", errors="replace")
    return csv.DictReader(io.StringIO(text))

def _parse_services(raw: bytes) -> list[Fact]:
    facts = []
    for row in _reader(raw):
        svc = (row.get("Name") or "").strip()
        if not svc:
            continue
        path = (row.get("PathName") or "").strip()
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, "service", svc),
            kind="service",
            label=f"service: {row.get('DisplayName','').strip() or svc}",
            attack_id=SERVICE_ATTACK,
            attrs={
                "name": svc,
                "display_name": (row.get("DisplayName") or "").strip(),
                "path": path,
                "start_mode": (row.get("StartMode") or "").strip(),
                "run_as": (row.get("StartName") or "").strip(),
                "service_type": (row.get("ServiceType") or "").strip(),
                "from_temp": is_tempish(path),
            },
            # Running/Stopped is scheduler state, not a property of the installed
            # service -- demand-start flips must not diff (ADR 0002 rule 3)
            observed={"state": (row.get("State") or "").strip()},
        ))
    return facts

def _parse_tasks(raw: bytes) -> list[Fact]:
    # `schtasks /query /v` emits ONE ROW PER TRIGGER, so a task with N triggers yields N
    # rows that differ only in Schedule Type (measured: task_to_run never diverged within
    # a group; schedule_type did in 34/46 multi-trigger tasks). A task is ONE persistence
    # entity, so FOLD the rows into one fact per task -- otherwise every row mints a fact
    # under the same entity_key, and both the baseline store (PRIMARY KEY + INSERT OR
    # REPLACE) and diff.py's dict build keep whichever row came LAST: 80 facts silently
    # dropped per scan, and the stored schedule_type decided by CSV row order (a reorder
    # between scans then fakes a "changed" -> a false +3 "new since baseline").
    # The fold keeps the task-name entity_key unchanged, so existing baselines survive;
    # schedule_type becomes the SORTED "; "-join of every trigger's schedule (stable
    # regardless of row order), and trigger_count records how many rows folded.
    rows_by_task: dict[str, list[dict]] = {}
    for row in _reader(raw):
        task = (row.get("TaskName") or "").strip()
        # schtasks repeats the header for every folder; skip those + blanks
        if not task or task == "TaskName":
            continue
        rows_by_task.setdefault(task, []).append(row)

    facts = []
    for task, rows in rows_by_task.items():
        first = rows[0]
        run = (first.get("Task To Run") or "").strip()
        schedules = sorted({s for r in rows
                            if (s := (r.get("Schedule Type") or "").strip())})
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, "task", task),
            kind="scheduled_task",
            label=f"task: {task}",
            attack_id=TASK_ATTACK,
            attrs={
                "name": task,
                "task_to_run": run,
                "author": (first.get("Author") or "").strip(),
                "run_as_user": (first.get("Run As User") or "").strip(),
                # Enabled/Disabled is CONFIG (someone toggled the task) -> diffed
                "state": (first.get("Scheduled Task State") or "").strip(),
                "schedule_type": "; ".join(schedules),
                "trigger_count": len(rows),
                "from_temp": is_tempish(run),
            },
            # Ready/Running and the last-run stamp change every time the task
            # fires on its own schedule -- zero-action churn, never diffed
            # (ADR 0002 rule 3; this was the every-scan last_run_time noise)
            observed={
                "status": (first.get("Status") or "").strip(),
                "last_run_time": (first.get("Last Run Time") or "").strip(),
            },
        ))
    return facts

def parse(raw: dict) -> list[Fact]:          # PURE
    raw = raw or {}
    return _parse_services(raw.get("services", b"")) + _parse_tasks(raw.get("tasks", b""))


class ServicesTasksCollector(Collector):
    """Windows services + scheduled tasks (PowerShell/schtasks). Ignores ctx."""
    name = "services_tasks"

    def gather(self, ctx: ScanContext) -> dict:
        return gather()

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
