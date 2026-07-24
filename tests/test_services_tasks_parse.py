from pathlib import Path
from spyscan.collectors.services_tasks import parse

FIX = Path(__file__).parent / "fixtures"

def _raw():
    return {
        "services": (FIX / "services_sample.csv").read_bytes(),
        "tasks": (FIX / "schtasks_sample.csv").read_bytes(),
    }

def test_parses_both_services_and_tasks():
    facts = parse(_raw())
    kinds = {f.kind for f in facts}
    assert "service" in kinds
    assert "scheduled_task" in kinds

def test_service_fact_fields_and_attack():
    facts = parse(_raw())
    svc = next(f for f in facts if f.kind == "service" and f.attrs["name"] == "EvilSvc")
    assert svc.attack_id == "T1543.003"
    assert "temp" in svc.attrs["path"].lower()
    assert svc.attrs["start_mode"] == "Auto"
    assert svc.observed["state"] == "Running"   # runtime state: never diffed
    assert "state" not in svc.attrs
    assert svc.entity_key.startswith("services_tasks::")


def test_task_runtime_churn_is_not_diffed():
    # a task firing on its own schedule (Status Ready->Running, new Last Run
    # Time) is zero-action churn; Enabled/Disabled stays a diffed config attr
    facts = parse(_raw())
    task = next(f for f in facts if f.kind == "scheduled_task")
    assert "last_run_time" not in task.attrs and "status" not in task.attrs
    assert "last_run_time" in task.observed and "status" in task.observed
    assert task.attrs["state"] in ("Enabled", "Disabled", "")

def test_task_fact_fields_and_attack():
    facts = parse(_raw())
    task = next(f for f in facts if f.kind == "scheduled_task"
               and f.attrs["name"] == "\\Evil Persistence")
    assert task.attack_id == "T1053.005"
    assert "temp" in task.attrs["task_to_run"].lower()
    assert task.attrs["run_as_user"] == "SYSTEM"

def _task_rows(rows: list[tuple[str, str, str]]) -> bytes:
    """Minimal schtasks /v CSV: (TaskName, Task To Run, Schedule Type) triples."""
    head = '"TaskName","Task To Run","Author","Run As User","Status","Scheduled Task State","Schedule Type","Last Run Time"\n'
    body = "".join(
        f'"{name}","{run}","a","SYSTEM","Ready","Enabled","{sched}","1/1/2026"\n'
        for name, run, sched in rows)
    return (head + body).encode()


def test_multi_trigger_task_folds_to_one_fact():
    """schtasks emits one row PER TRIGGER; a task is ONE persistence entity.

    Before the fold, N trigger rows minted N facts under the SAME entity_key --
    measured live: 295 task facts, 215 distinct keys, 80 silently dropped by the
    baseline store's INSERT OR REPLACE and diff.py's dict build, with the surviving
    schedule_type decided by CSV row order.
    """
    raw = {"services": b"", "tasks": _task_rows([
        (r"\Multi", r"C:\x\a.exe", "At logon time"),
        (r"\Multi", r"C:\x\a.exe", "One Time Only, Hourly"),
        (r"\Multi", r"C:\x\a.exe", "At logon time"),   # repeated schedule dedupes too
        (r"\Solo",  r"C:\y\b.exe", "Daily"),
    ])}
    facts = parse(raw)
    assert len(facts) == 2
    assert len({f.entity_key for f in facts}) == 2     # no colliding keys
    multi = next(f for f in facts if f.attrs["name"] == r"\Multi")
    # sorted, deduped, order-independent -- a schtasks row reorder changes NOTHING
    assert multi.attrs["schedule_type"] == "At logon time; One Time Only, Hourly"
    assert multi.attrs["trigger_count"] == 3
    solo = next(f for f in facts if f.attrs["name"] == r"\Solo")
    assert solo.attrs["schedule_type"] == "Daily"
    assert solo.attrs["trigger_count"] == 1


def test_folded_schedule_is_row_order_independent():
    """The exact flake the old code had: stored attrs must not depend on row order."""
    rows = [(r"\T", r"C:\x\a.exe", "Hourly"), (r"\T", r"C:\x\a.exe", "At logon time")]
    a = parse({"services": b"", "tasks": _task_rows(rows)})
    b = parse({"services": b"", "tasks": _task_rows(rows[::-1])})
    assert a[0].attrs == b[0].attrs


def test_skips_blank_rows():
    raw = {"services": b'"Name","DisplayName","PathName","StartMode","State","StartName","ServiceType"\n"","","","","","",""\n',
           "tasks": b""}
    assert parse(raw) == []
