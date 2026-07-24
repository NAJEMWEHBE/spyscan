# Spy-Detector (spyscan) — Phase 0 + Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A local-only Windows CLI that snapshots a clean machine, then on later scans flags NEW/suspicious autostarts, processes, network connections, drivers, and webcam/mic usage — scoring each finding and producing a JSON + HTML "is my device being spied on?" report.

**Architecture:** Canonical EDR spine, usermode/scanner-grade (honest: not a kernel EDR). `collectors → normalize(facts) → baseline-diff + rule/IOC + behavioral → per-entity score → JSON+HTML report`. Every collector splits into `gather()` (impure: shell-out/API) and `parse()` (pure: bytes/objects → canonical facts) so the parsers are unit-tested with fixtures and the impure edge stays thin. SQLite store, no server. Defensive only — consumes published indicators, never replicates offense, never sends data off-box.

**Tech Stack:** Python 3.14, stdlib (`sqlite3`, `csv`, `json`, `hashlib`, `subprocess`, `html`, `pathlib`), `psutil` (processes/connections), `pefile` (PE metadata). Shell-out to Sysinternals `autorunsc64.exe` and PowerShell `Get-AuthenticodeSignature`/`Get-NetTCPConnection`. Test: `pytest`. Phase-2 deps (`yara-python`, Sigma) are out of scope here.

**Source of truth:** `docs/GROUNDING-BRIEF.md` (§2 signal catalog, §3 OSS tools+licenses, §6 architecture/roadmap), `docs/ADVANCED-THREAT-BRIEF.md` (mercenary/APT IOCs), `docs/DESIGN-DECISIONS.md`.

---

## Ground rules (read before any task)

1. **TDD.** Pure logic (schema, diff, score, every `parse()`) is unit-tested with fixtures FIRST. Impure `gather()` functions get one integration smoke test guarded by `@pytest.mark.integration` (they hit the real OS; skipped in CI).
2. **The gather/parse seam is mandatory.** A collector module exposes `gather() -> bytes|list[obj]` (impure) and `parse(raw) -> list[Fact]` (pure). Tests target `parse()`.
3. **Local-only.** No network calls except the explicit IOC-feed updater (Phase 2). No telemetry. Reports written under the project's `runs/` dir only.
4. **Allowlist before alarm.** Microsoft-signed + known-good-hash entities are scored down. Every finding carries human-readable `evidence` and a MITRE `attack_id` so the user can judge.
5. **Honest limits in every report.** Footer states: usermode scanner, can miss kernel-hidden implants; a clean result ≠ a clean device.
6. **Exact paths.** All code under `F:\ai\spy-detector\`. Python package root: `src/spyscan/`. Tests: `tests/`.
7. **Commit after every green task.** `git init` happens in Task 0.

---

## File structure (locked before tasks)

```
F:\ai\spy-detector\
  pyproject.toml                 # package metadata + deps + pytest config
  src/spyscan/
    __init__.py
    facts.py                     # Fact dataclass + canonical schema (PURE)
    store.py                     # SQLite baseline save/load (impure I/O, thin)
    diff.py                      # baseline vs current -> added/removed/changed (PURE)
    score.py                     # weighted per-entity scoring + allowlist (PURE)
    collectors/
      __init__.py                # COLLECTORS registry
      base.py                    # Collector protocol (gather/parse contract)
      autoruns.py                # autorunsc64.exe CSV -> facts
      processes.py               # psutil -> facts
      netconns.py                # psutil/Get-NetTCPConnection -> facts
      services_tasks.py          # services + scheduled tasks -> facts
      drivers.py                 # driverquery -> facts
      consentstore.py            # webcam/mic ConsentStore registry -> facts
    enrich/
      signature.py              # Authenticode signer/verify (shell-out + parse)
      hashing.py                 # sha256 of a file (PURE-ish, fs read)
    rules/
      ioc.py                     # set-membership vs local domain/ip/hash lists (PURE)
      indicators/                # bundled IOC lists (mercenary domains, impl names)
        mercenary_domains.txt
        mercenary_procnames.txt
    report/
      html.py                    # facts+scores -> self-contained HTML (PURE)
      json_out.py                # findings -> JSON (PURE)
    cli.py                       # argparse: baseline | scan | report
  tests/
    conftest.py
    fixtures/                    # sample autorunsc CSV, psutil stubs, registry dumps
    test_facts.py  test_diff.py  test_score.py
    test_autoruns_parse.py  test_processes_parse.py  test_netconns_parse.py
    test_consentstore_parse.py  test_ioc.py  test_html.py  test_signature_parse.py
  tools/
    autorunsc64.exe              # user-dropped Sysinternals binary (gitignored)
  runs/                          # scan outputs (gitignored)
  baseline.db                    # SQLite snapshot (gitignored)
```

---

## Canonical Fact schema (the contract every collector returns)

```python
# Fact: one observed thing on the machine, normalized across collectors.
# entity_key = stable identity used for baseline diffing (must be deterministic).
{
  "collector":  str,    # "autoruns" | "processes" | "netconns" | ...
  "entity_key": str,    # stable id, e.g. "autoruns::HKLM\\...\\Run::Updater"
  "kind":       str,    # "autostart" | "process" | "connection" | "service" | "driver" | "device_use"
  "label":      str,    # human name, e.g. "Updater (C:\\Temp\\u.exe)"
  "attrs":      dict,   # collector-specific fields (path, hash, signer, remote_ip, ...)
  "attack_id":  str|None # MITRE technique tag if the collector knows it, else None
}
```

---

# MILESTONE A — Phase 0: autoruns baseline-diff (smallest real detector)

Outcome: `spyscan baseline` then `spyscan scan` reports NEW autostart entries since baseline. Covers ~70% of spyware persistence with the least code.

### Task 0: Project scaffold + repo

**Files:**
- Create: `F:\ai\spy-detector\pyproject.toml`
- Create: `F:\ai\spy-detector\.gitignore`
- Create: `F:\ai\spy-detector\src\spyscan\__init__.py`
- Create: `F:\ai\spy-detector\tests\conftest.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "spyscan"
version = "0.0.1"
description = "Local-only Windows spyware/surveillance awareness scanner (defensive)."
requires-python = ">=3.13"
dependencies = ["psutil>=5.9", "pefile>=2023.2.7"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[project.scripts]
spyscan = "spyscan.cli:main"

[tool.pytest.ini_options]
pythonpath = ["src"]
markers = ["integration: hits the real OS; skipped by default"]
addopts = "-m 'not integration'"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
__pycache__/
*.pyc
.venv/
baseline.db
runs/
tools/*.exe
.pytest_cache/
```

- [ ] **Step 3: Empty package + conftest**

`src/spyscan/__init__.py`:
```python
__version__ = "0.0.1"
```
`tests/conftest.py`:
```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
```

- [ ] **Step 4: Create venv, install, verify pytest runs**

Run:
```bash
cd /f/ai/spy-detector
py -3.14 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest -q
```
Expected: `no tests ran` (exit 5) — environment works.

- [ ] **Step 5: Commit**

```bash
cd /f/ai/spy-detector && git init && git add -A && git commit -m "chore: scaffold spyscan package + pytest"
```

---

### Task 1: Fact schema + helpers (PURE, tested)

**Files:**
- Create: `src/spyscan/facts.py`
- Test: `tests/test_facts.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_facts.py
from spyscan.facts import Fact, make_key

def test_make_key_is_stable_and_namespaced():
    k1 = make_key("autoruns", "HKLM\\Run", "Updater")
    k2 = make_key("autoruns", "HKLM\\Run", "Updater")
    assert k1 == k2
    assert k1.startswith("autoruns::")

def test_fact_to_dict_roundtrip():
    f = Fact(collector="autoruns", entity_key="autoruns::a::b",
             kind="autostart", label="Updater", attrs={"path": "c:\\u.exe"},
             attack_id="T1547.001")
    d = f.to_dict()
    assert d["attack_id"] == "T1547.001"
    assert Fact.from_dict(d) == f
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/test_facts.py -q`
Expected: FAIL `ModuleNotFoundError: No module named 'spyscan.facts'`

- [ ] **Step 3: Implement `facts.py`**

```python
# src/spyscan/facts.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict

def make_key(collector: str, *parts: str) -> str:
    """Deterministic, namespaced entity identity for baseline diffing."""
    return collector + "::" + "::".join(p.strip() for p in parts)

@dataclass(frozen=True)
class Fact:
    collector: str
    entity_key: str
    kind: str
    label: str
    attrs: dict = field(default_factory=dict)
    attack_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Fact":
        return cls(
            collector=d["collector"], entity_key=d["entity_key"],
            kind=d["kind"], label=d["label"],
            attrs=dict(d.get("attrs", {})), attack_id=d.get("attack_id"),
        )

    def __eq__(self, other):  # frozen dataclass with dict field needs explicit eq
        return isinstance(other, Fact) and self.to_dict() == other.to_dict()

    def __hash__(self):
        return hash(self.entity_key)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python -m pytest tests/test_facts.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/spyscan/facts.py tests/test_facts.py && git commit -m "feat: canonical Fact schema + stable keys"
```

---

### Task 2: SQLite baseline store

**Files:**
- Create: `src/spyscan/store.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_store.py
from spyscan.facts import Fact
from spyscan.store import BaselineStore

def test_save_and_load_roundtrip(tmp_path):
    db = tmp_path / "b.db"
    s = BaselineStore(db)
    facts = [Fact("autoruns", "autoruns::a::b", "autostart", "X", {"path": "c:\\x"}, "T1547.001")]
    s.save_baseline(facts)
    loaded = s.load_baseline()
    assert loaded == facts

def test_load_empty_returns_empty_list(tmp_path):
    s = BaselineStore(tmp_path / "none.db")
    assert s.load_baseline() == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/test_store.py -q`
Expected: FAIL `No module named 'spyscan.store'`

- [ ] **Step 3: Implement `store.py`**

```python
# src/spyscan/store.py
from __future__ import annotations
import sqlite3, json
from pathlib import Path
from spyscan.facts import Fact

class BaselineStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._init()

    def _init(self):
        with sqlite3.connect(self.db_path) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS baseline(
                entity_key TEXT PRIMARY KEY, fact_json TEXT NOT NULL)""")

    def save_baseline(self, facts: list[Fact]) -> None:
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM baseline")
            c.executemany(
                "INSERT OR REPLACE INTO baseline VALUES (?, ?)",
                [(f.entity_key, json.dumps(f.to_dict())) for f in facts],
            )

    def load_baseline(self) -> list[Fact]:
        with sqlite3.connect(self.db_path) as c:
            rows = c.execute("SELECT fact_json FROM baseline").fetchall()
        return [Fact.from_dict(json.loads(r[0])) for r in rows]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python -m pytest tests/test_store.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/spyscan/store.py tests/test_store.py && git commit -m "feat: SQLite baseline store"
```

---

### Task 3: Baseline diff (PURE, tested)

**Files:**
- Create: `src/spyscan/diff.py`
- Test: `tests/test_diff.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_diff.py
from spyscan.facts import Fact
from spyscan.diff import diff_facts

def f(key, **attrs):
    return Fact("c", key, "autostart", key, attrs)

def test_added_removed_changed():
    base = [f("a", path="x"), f("b", path="y")]
    curr = [f("b", path="CHANGED"), f("c", path="z")]
    d = diff_facts(base, curr)
    assert {x.entity_key for x in d["added"]} == {"c"}
    assert {x.entity_key for x in d["removed"]} == {"a"}
    assert [x.entity_key for x in d["changed"]] == ["b"]

def test_identical_baseline_is_clean():
    base = [f("a", path="x")]
    d = diff_facts(base, list(base))
    assert d == {"added": [], "removed": [], "changed": []}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/test_diff.py -q`
Expected: FAIL `No module named 'spyscan.diff'`

- [ ] **Step 3: Implement `diff.py`**

```python
# src/spyscan/diff.py
from __future__ import annotations
from spyscan.facts import Fact

def diff_facts(baseline: list[Fact], current: list[Fact]) -> dict[str, list[Fact]]:
    """Compare by entity_key. 'changed' = same key, different attrs."""
    base = {f.entity_key: f for f in baseline}
    curr = {f.entity_key: f for f in current}
    added   = [curr[k] for k in curr.keys() - base.keys()]
    removed = [base[k] for k in base.keys() - curr.keys()]
    changed = [curr[k] for k in base.keys() & curr.keys()
               if curr[k].attrs != base[k].attrs]
    keyfn = lambda f: f.entity_key
    return {"added": sorted(added, key=keyfn),
            "removed": sorted(removed, key=keyfn),
            "changed": sorted(changed, key=keyfn)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python -m pytest tests/test_diff.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/spyscan/diff.py tests/test_diff.py && git commit -m "feat: baseline diff (added/removed/changed)"
```

---

### Task 4: autoruns parser (PURE, fixture-tested)

> The collector splits into `gather()` (runs `autorunsc64.exe`, impure) and `parse(csv_bytes)` (pure). We test `parse()` against a captured CSV fixture. `autorunsc -a * -c -h -s -nobanner` emits CSV; we parse with `csv.DictReader` and map by header NAME (order-independent, robust to version drift).

**Files:**
- Create: `tests/fixtures/autorunsc_sample.csv`
- Create: `src/spyscan/collectors/__init__.py` (empty for now)
- Create: `src/spyscan/collectors/base.py`
- Create: `src/spyscan/collectors/autoruns.py`
- Test: `tests/test_autoruns_parse.py`

- [ ] **Step 1: Capture a REAL header sample (one-time, integration)**

Run (after dropping `autorunsc64.exe` into `tools/`):
```bash
cd /f/ai/spy-detector
tools/autorunsc64.exe -accepteula -a * -c -h -s -nobanner > tests/fixtures/autorunsc_real.csv 2>/dev/null
head -1 tests/fixtures/autorunsc_real.csv
```
Expected: a CSV header line. Copy 2–3 representative rows into `tests/fixtures/autorunsc_sample.csv` (below) and **confirm the column names** match — adjust the `COLS` mapping in Step 3 if your Sysinternals build differs.

- [ ] **Step 2: Write the fixture + failing test**

`tests/fixtures/autorunsc_sample.csv` (representative; trim to real headers):
```csv
Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String,Verified,Signer,MD5,SHA-256
"","HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","SecurityHealth","enabled","Logon","System-wide","Windows Security notification icon","Microsoft Corporation","c:\windows\system32\securityhealthsystray.exe","","%windir%\system32\SecurityHealthSystray.exe","(Verified)","Microsoft Windows","ABC","1111"
"","HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","Updater","enabled","Logon","User","","","c:\users\testuser\appdata\local\temp\u.exe","","C:\Users\testuser\AppData\Local\Temp\u.exe","(Not verified)","","DEF","2222"
```

`tests/test_autoruns_parse.py`:
```python
from pathlib import Path
from spyscan.collectors.autoruns import parse

def test_parse_maps_rows_to_facts():
    raw = (Path(__file__).parent / "fixtures/autorunsc_sample.csv").read_bytes()
    facts = parse(raw)
    by_label = {f.attrs["entry"]: f for f in facts}
    assert "Updater" in by_label
    upd = by_label["Updater"]
    assert upd.kind == "autostart"
    assert upd.attack_id == "T1547.001"
    assert upd.attrs["sha256"] == "2222"
    assert upd.attrs["verified"] is False
    assert "temp" in upd.attrs["image_path"].lower()

def test_parse_marks_microsoft_signed_verified_true():
    raw = (Path(__file__).parent / "fixtures/autorunsc_sample.csv").read_bytes()
    facts = parse(raw)
    sec = next(f for f in facts if f.attrs["entry"] == "SecurityHealth")
    assert sec.attrs["verified"] is True
    assert sec.attrs["signer"] == "Microsoft Windows"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/test_autoruns_parse.py -q`
Expected: FAIL `No module named 'spyscan.collectors.autoruns'`

- [ ] **Step 4: Implement `base.py` + `autoruns.py`**

`src/spyscan/collectors/base.py`:
```python
from __future__ import annotations
from typing import Protocol
from spyscan.facts import Fact

class Collector(Protocol):
    name: str
    def gather(self) -> object: ...          # impure: returns raw (bytes/objs)
    def parse(self, raw: object) -> list[Fact]: ...  # pure: raw -> facts
```

`src/spyscan/collectors/autoruns.py`:
```python
from __future__ import annotations
import csv, io, subprocess
from pathlib import Path
from spyscan.facts import Fact, make_key

name = "autoruns"
ATTACK = "T1547.001"   # Boot or Logon Autostart Execution: Registry Run/Startup
AUTORUNSC = Path(__file__).resolve().parents[3] / "tools" / "autorunsc64.exe"

def gather() -> bytes:                       # impure edge (integration-tested)
    out = subprocess.run(
        [str(AUTORUNSC), "-accepteula", "-a", "*", "-c", "-h", "-s", "-nobanner"],
        capture_output=True, timeout=180)
    return out.stdout

def _truthy_verified(v: str) -> bool:
    return "(verified)" in (v or "").strip().lower()

def parse(raw: bytes) -> list[Fact]:         # PURE
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    facts: list[Fact] = []
    for row in reader:
        loc = (row.get("Entry Location") or "").strip()
        entry = (row.get("Entry") or "").strip()
        if not entry and not loc:
            continue
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, loc, entry),
            kind="autostart",
            label=f"{entry} ({row.get('Image Path','').strip()})",
            attack_id=ATTACK,
            attrs={
                "entry": entry,
                "location": loc,
                "image_path": (row.get("Image Path") or "").strip(),
                "launch_string": (row.get("Launch String") or "").strip(),
                "company": (row.get("Company") or "").strip(),
                "signer": (row.get("Signer") or "").strip(),
                "verified": _truthy_verified(row.get("Verified", "")),
                "sha256": (row.get("SHA-256") or row.get("SHA256") or "").strip(),
                "md5": (row.get("MD5") or "").strip(),
                "enabled": (row.get("Enabled") or "").strip().lower() == "enabled",
            },
        ))
    return facts
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv/Scripts/python -m pytest tests/test_autoruns_parse.py -q`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add src/spyscan/collectors tests/test_autoruns_parse.py tests/fixtures/autorunsc_sample.csv && git commit -m "feat: autoruns collector (gather/parse seam, fixture-tested)"
```

---

### Task 5: Phase-0 CLI (`baseline` / `scan`) + smoke

**Files:**
- Create: `src/spyscan/cli.py`
- Test: `tests/test_cli_phase0.py`

- [ ] **Step 1: Write the failing test** (drives a clean `scan` reporting one new autostart)

```python
# tests/test_cli_phase0.py
from spyscan.facts import Fact
from spyscan.store import BaselineStore
from spyscan.diff import diff_facts

def test_scan_flags_new_autostart(tmp_path):
    store = BaselineStore(tmp_path / "b.db")
    base = [Fact("autoruns", "autoruns::HKLM::A", "autostart", "A", {"verified": True})]
    store.save_baseline(base)
    current = base + [Fact("autoruns", "autoruns::HKCU::Evil", "autostart",
                           "Evil", {"verified": False, "image_path": "c:\\temp\\e.exe"})]
    d = diff_facts(store.load_baseline(), current)
    assert [x.entity_key for x in d["added"]] == ["autoruns::HKCU::Evil"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/test_cli_phase0.py -q`
Expected: FAIL (import error until cli exists — though this test only uses store/diff, add the cli import line below to force the dependency)

Add at top of the test: `from spyscan import cli  # noqa`  → now it fails on missing `cli`.

- [ ] **Step 3: Implement `cli.py` (Phase-0 subset)**

```python
# src/spyscan/cli.py
from __future__ import annotations
import argparse, json
from pathlib import Path
from spyscan.store import BaselineStore
from spyscan.diff import diff_facts
from spyscan.collectors import autoruns

ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / "baseline.db"

def _collect_all():
    facts = []
    facts += autoruns.parse(autoruns.gather())
    return facts

def cmd_baseline(args):
    store = BaselineStore(DB)
    facts = _collect_all()
    store.save_baseline(facts)
    print(f"baseline saved: {len(facts)} facts -> {DB}")

def cmd_scan(args):
    store = BaselineStore(DB)
    base = store.load_baseline()
    if not base:
        print("no baseline yet — run: spyscan baseline"); return 2
    current = _collect_all()
    d = diff_facts(base, current)
    print(f"NEW: {len(d['added'])}  REMOVED: {len(d['removed'])}  CHANGED: {len(d['changed'])}")
    for f in d["added"]:
        print(f"  [NEW] {f.label}")
    (ROOT / "runs").mkdir(exist_ok=True)
    out = ROOT / "runs" / "last_scan.json"
    out.write_text(json.dumps({k: [x.to_dict() for x in v] for k, v in d.items()}, indent=2))
    print(f"report: {out}")
    return 0

def main(argv=None):
    p = argparse.ArgumentParser(prog="spyscan")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline").set_defaults(func=cmd_baseline)
    sub.add_parser("scan").set_defaults(func=cmd_scan)
    args = p.parse_args(argv)
    return args.func(args) or 0

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run unit test + a real integration smoke**

Run: `.venv/Scripts/python -m pytest tests/test_cli_phase0.py -q`  → Expected: PASS
Then prove it OPERATES on the real box (needs `tools/autorunsc64.exe`):
```bash
.venv/Scripts/python -m spyscan.cli baseline
.venv/Scripts/python -m spyscan.cli scan
```
Expected: `baseline saved: N facts` then `NEW: 0 REMOVED: 0 CHANGED: 0` and a `runs/last_scan.json`. (Add a junk `HKCU\...\Run` value, re-scan, confirm it shows `[NEW]`, then delete it.)

- [ ] **Step 5: Commit**

```bash
git add src/spyscan/cli.py tests/test_cli_phase0.py && git commit -m "feat: Phase-0 CLI baseline+scan (autoruns diff)"
```

**Milestone A done:** real persistence-change detection, end to end. Everything below enriches signal and scoring.

---

# MILESTONE B — Phase 1 MVP (richer collectors + scoring + report)

Each collector follows the Task-4 pattern: `gather()` impure, `parse()` pure + fixture-tested, returns canonical Facts. Add each to the `COLLECTORS` registry and to `cli._collect_all()`.

### Task 6: collectors registry

**Files:** Modify `src/spyscan/collectors/__init__.py`; Test `tests/test_registry.py`

- [ ] **Step 1: Failing test**
```python
# tests/test_registry.py
from spyscan.collectors import COLLECTORS
def test_registry_lists_autoruns():
    assert "autoruns" in {c.name for c in COLLECTORS}
```
- [ ] **Step 2: Run** → FAIL (`COLLECTORS` undefined).
- [ ] **Step 3: Implement**
```python
# src/spyscan/collectors/__init__.py
from spyscan.collectors import autoruns
COLLECTORS = [autoruns]          # append each new collector module here
```
- [ ] **Step 4: Run** → PASS. Refactor `cli._collect_all()` to iterate `COLLECTORS`:
```python
def _collect_all():
    facts = []
    for c in COLLECTORS:
        try:
            facts += c.parse(c.gather())
        except Exception as e:          # one collector failing must not kill the scan
            print(f"  [warn] collector {c.name} failed: {e}")
    return facts
```
(Add `from spyscan.collectors import COLLECTORS` to cli imports; drop the direct autoruns import.)
- [ ] **Step 5: Commit** `feat: collector registry + resilient _collect_all`

---

### Task 7: processes collector

**Files:** Create `src/spyscan/collectors/processes.py`; Test `tests/test_processes_parse.py`
Signal (GROUNDING §2.1): exec from `%TEMP%`/AppData, no trusted parent, unsigned. `gather()` returns `list[dict]` snapshots from `psutil`; `parse()` is pure over those dicts.

- [ ] **Step 1: Failing test**
```python
# tests/test_processes_parse.py
from spyscan.collectors.processes import parse
def sample():
    return [
        {"pid": 1000, "name": "u.exe", "exe": r"C:\Users\n\AppData\Local\Temp\u.exe",
         "ppid": 4, "pname": "services.exe", "cmdline": ["u.exe", "-hidden"]},
        {"pid": 1, "name": "explorer.exe", "exe": r"C:\Windows\explorer.exe",
         "ppid": 800, "pname": "userinit.exe", "cmdline": ["explorer.exe"]},
    ]
def test_flags_temp_path_attr():
    facts = {f.attrs["pid"]: f for f in parse(sample())}
    assert facts[1000].attrs["from_temp"] is True
    assert facts[1].attrs["from_temp"] is False
def test_kind_and_key():
    f = parse(sample())[0]
    assert f.kind == "process"
    assert f.entity_key.startswith("processes::")
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/collectors/processes.py
from __future__ import annotations
import os
import psutil
from spyscan.facts import Fact, make_key

name = "processes"
_TEMPISH = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\appdata\\roaming\\")

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

def parse(snaps: list[dict]) -> list[Fact]:
    facts = []
    for s in snaps:
        exe = (s.get("exe") or "")
        low = exe.lower()
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, s.get("name", ""), os.path.basename(low)),
            kind="process",
            label=f"{s.get('name','?')} (pid {s.get('pid')})",
            attack_id=None,
            attrs={
                "pid": s.get("pid"), "exe": exe, "parent": s.get("pname", ""),
                "cmdline": " ".join(s.get("cmdline") or []),
                "from_temp": any(t in low for t in _TEMPISH),
                "hidden_flag": "-hidden" in (s.get("cmdline") or []),
            },
        ))
    return facts
```
- [ ] **Step 4: Run** → PASS. Append `processes` to `COLLECTORS`.
- [ ] **Step 5: Commit** `feat: processes collector (temp-path/parent signal)`

---

### Task 8: netconns collector

**Files:** Create `src/spyscan/collectors/netconns.py`; Test `tests/test_netconns_parse.py`
Signal (GROUNDING §2): remote ip:port + owning pid; listening ports. `gather()` = `psutil.net_connections(kind="inet")`; `parse()` over normalized dicts.

- [ ] **Step 1: Failing test**
```python
# tests/test_netconns_parse.py
from spyscan.collectors.netconns import parse
def test_remote_conn_becomes_fact():
    snaps = [{"pid": 1000, "laddr": "192.168.1.5:55000", "raddr": "13.37.13.37:443",
              "status": "ESTABLISHED", "pname": "u.exe"}]
    f = parse(snaps)[0]
    assert f.kind == "connection"
    assert f.attrs["remote_ip"] == "13.37.13.37"
    assert f.attrs["remote_port"] == 443
def test_listening_has_no_remote():
    snaps = [{"pid": 5, "laddr": "0.0.0.0:3389", "raddr": "", "status": "LISTEN", "pname": "svc"}]
    f = parse(snaps)[0]
    assert f.attrs["listening"] is True
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/collectors/netconns.py
from __future__ import annotations
import psutil
from spyscan.facts import Fact, make_key

name = "netconns"

def gather() -> list[dict]:
    out = []
    for c in psutil.net_connections(kind="inet"):
        try:
            pname = psutil.Process(c.pid).name() if c.pid else ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pname = ""
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        out.append({"pid": c.pid, "laddr": laddr, "raddr": raddr,
                    "status": c.status, "pname": pname})
    return out

def parse(snaps: list[dict]) -> list[Fact]:
    facts = []
    for s in snaps:
        raddr = s.get("raddr") or ""
        rip, _, rport = raddr.rpartition(":")
        listening = (s.get("status") == "LISTEN") or not raddr
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, s.get("pname", ""), raddr or s.get("laddr", "")),
            kind="connection",
            label=f"{s.get('pname','?')} -> {raddr or '(listen) ' + s.get('laddr','')}",
            attack_id="T1071" if raddr else None,
            attrs={"pid": s.get("pid"), "process": s.get("pname", ""),
                   "remote_ip": rip, "remote_port": int(rport) if rport.isdigit() else None,
                   "local": s.get("laddr", ""), "status": s.get("status"),
                   "listening": listening},
        ))
    return facts
```
- [ ] **Step 4: Run** → PASS. Append to `COLLECTORS`.
- [ ] **Step 5: Commit** `feat: netconns collector (remote endpoint + owning proc)`

---

### Task 9: consentstore collector (webcam/mic usage)

**Files:** Create `src/spyscan/collectors/consentstore.py`; Test `tests/test_consentstore_parse.py`
Signal (GROUNDING §2.4 / ATT&CK T1125 video, T1123 audio): registry `HKCU/HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{webcam,microphone}\<app>` — `LastUsedTimeStop == 0` means **in use right now**. `gather()` walks the registry via `winreg`; `parse()` over `(scope, capability, app, start, stop)` tuples.

- [ ] **Step 1: Failing test**
```python
# tests/test_consentstore_parse.py
from spyscan.collectors.consentstore import parse
def test_in_use_when_stop_zero():
    rows = [("HKCU", "webcam", "C#Program Files#evil#cam.exe", 132000000000000, 0)]
    f = parse(rows)[0]
    assert f.kind == "device_use"
    assert f.attrs["in_use_now"] is True
    assert f.attrs["capability"] == "webcam"
    assert f.attack_id == "T1125"
def test_not_in_use_when_stop_nonzero():
    rows = [("HKCU", "microphone", "App", 132000000000000, 132000000000001)]
    assert parse(rows)[0].attrs["in_use_now"] is False
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/collectors/consentstore.py
from __future__ import annotations
from spyscan.facts import Fact, make_key

name = "consentstore"
_ATTACK = {"webcam": "T1125", "microphone": "T1123"}

def gather() -> list[tuple]:                 # impure: walk registry
    import winreg
    rows = []
    bases = [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    root = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    for hive, scope in bases:
        for cap in ("webcam", "microphone"):
            try:
                k = winreg.OpenKey(hive, root + "\\" + cap)
            except OSError:
                continue
            i = 0
            while True:
                try:
                    app = winreg.EnumKey(k, i); i += 1
                except OSError:
                    break
                try:
                    ak = winreg.OpenKey(hive, f"{root}\\{cap}\\{app}")
                    start = _rd(winreg, ak, "LastUsedTimeStart")
                    stop = _rd(winreg, ak, "LastUsedTimeStop")
                    rows.append((scope, cap, app, start, stop))
                except OSError:
                    continue
    return rows

def _rd(winreg, key, val):
    try:
        return winreg.QueryValueEx(key, val)[0]
    except OSError:
        return None

def parse(rows: list[tuple]) -> list[Fact]:
    facts = []
    for scope, cap, app, start, stop in rows:
        app_name = app.replace("#", "\\")
        facts.append(Fact(
            collector=name,
            entity_key=make_key(name, cap, app),
            kind="device_use",
            label=f"{cap}: {app_name}",
            attack_id=_ATTACK.get(cap),
            attrs={"scope": scope, "capability": cap, "app": app_name,
                   "last_start": start, "last_stop": stop,
                   "in_use_now": stop == 0},
        ))
    return facts
```
- [ ] **Step 4: Run** → PASS. Append to `COLLECTORS`.
- [ ] **Step 5: Commit** `feat: consentstore collector (live webcam/mic usage)`

> NOTE for executor: `services_tasks.py` and `drivers.py` follow the identical pattern (`gather` shells `schtasks /query /fo csv /v`, `sc query`/`driverquery /fo csv`; `parse` is a `csv.DictReader` mapper like Task 4). Implement them as Tasks 9b/9c with their own fixtures BEFORE Task 12 if time allows; they are not required for the first scored report.

---

### Task 10: signature enrichment (Authenticode)

**Files:** Create `src/spyscan/enrich/signature.py`, `src/spyscan/enrich/hashing.py`; Test `tests/test_signature_parse.py`
Shell out to PowerShell `Get-AuthenticodeSignature` (no extra dep); `parse()` over its output. Pure parser tested with captured strings.

- [ ] **Step 1: Failing test**
```python
# tests/test_signature_parse.py
from spyscan.enrich.signature import parse_status
def test_valid_microsoft():
    line = "Valid|Microsoft Windows"
    s = parse_status(line)
    assert s["signed"] is True and s["trusted_ms"] is True
def test_unsigned():
    s = parse_status("NotSigned|")
    assert s["signed"] is False and s["trusted_ms"] is False
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/enrich/hashing.py
import hashlib
from pathlib import Path
def sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
```
```python
# src/spyscan/enrich/signature.py
from __future__ import annotations
import subprocess

def parse_status(line: str) -> dict:
    """line = '<Status>|<SignerSubject>' from Get-AuthenticodeSignature."""
    status, _, signer = line.partition("|")
    status = status.strip()
    signer = signer.strip()
    signed = status.lower() == "valid"
    trusted_ms = signed and "microsoft" in signer.lower()
    return {"signed": signed, "status": status, "signer": signer,
            "trusted_ms": trusted_ms}

def authenticode(path: str) -> dict:         # impure edge
    ps = (f"$s=Get-AuthenticodeSignature -LiteralPath '{path}';"
          f"\"$($s.Status)|$($s.SignerCertificate.Subject)\"")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=20)
        return parse_status(out.stdout.strip())
    except Exception:
        return {"signed": False, "status": "error", "signer": "", "trusted_ms": False}
```
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Authenticode signature enrichment + sha256`

---

### Task 11: IOC engine (local lists, incl. mercenary indicators)

**Files:** Create `src/spyscan/rules/ioc.py`, `src/spyscan/rules/indicators/mercenary_domains.txt`, `.../mercenary_procnames.txt`; Test `tests/test_ioc.py`
Seed lists from `ADVANCED-THREAT-BRIEF.md` §1 (defensive IOCs): domains e.g. `free247downloads.com`, `urlpush.net`, `sec-flare.com`, `noc-service-streamer.com`; process names e.g. `bh`, `roleaccountd`, `stagingd`, `msgacntd`. `parse`/match is pure set-membership.

- [ ] **Step 1: Failing test**
```python
# tests/test_ioc.py
from spyscan.rules.ioc import IOCMatcher
def test_domain_and_proc_hits():
    m = IOCMatcher(domains={"sec-flare.com"}, procnames={"roleaccountd"})
    assert m.match_domain("login.sec-flare.com") is True   # suffix match
    assert m.match_domain("apple.com") is False
    assert m.match_proc("roleaccountd") is True
    assert m.match_proc("explorer.exe") is False
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/rules/ioc.py
from __future__ import annotations
from pathlib import Path

class IOCMatcher:
    def __init__(self, domains: set[str] | None = None, procnames: set[str] | None = None,
                 hashes: set[str] | None = None):
        self.domains = {d.lower().lstrip(".") for d in (domains or set())}
        self.procnames = {p.lower() for p in (procnames or set())}
        self.hashes = {h.lower() for h in (hashes or set())}

    @classmethod
    def from_dir(cls, d: Path) -> "IOCMatcher":
        def load(name):
            f = d / name
            return {l.strip().lower() for l in f.read_text().splitlines()
                    if l.strip() and not l.startswith("#")} if f.exists() else set()
        return cls(load("mercenary_domains.txt"), load("mercenary_procnames.txt"),
                   load("mercenary_hashes.txt"))

    def match_domain(self, host: str) -> bool:
        h = (host or "").lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def match_proc(self, name: str) -> bool:
        n = (name or "").lower()
        return n in self.procnames or n.removesuffix(".exe") in self.procnames

    def match_hash(self, sha: str) -> bool:
        return (sha or "").lower() in self.hashes
```
`mercenary_domains.txt` (defensive IOC seed — cite source in a header comment):
```
# Mercenary-spyware C2/exploit domains. Source: Amnesty/Citizen Lab/Google TAG/MSTIC.
# DEFENSIVE detection only.
free247downloads.com
urlpush.net
opposedarrangement.net
documentpro.org
sec-flare.com
noc-service-streamer.com
fbcdnads.live
hilocake.info
grayhornet.com
johnshopkin.net
```
`mercenary_procnames.txt`:
```
# Disguised iOS implant daemon names (Pegasus-class). Source: Amnesty Forensic Methodology Report.
bh
roleaccountd
roleaboutd
stagingd
msgacntd
mptbd
ckkeyrollfd
fmld
pcsd
otpgrefd
gatekeeperd
```
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: IOC matcher + bundled mercenary indicators (cited)`

---

### Task 12: scoring engine (PURE, tested)

**Files:** Create `src/spyscan/score.py`; Test `tests/test_score.py`
Weights (GROUNDING §6): unsigned +2, new-since-baseline +3, beacon/remote to IOC domain +3, IOC hash hit +5, runs from `%TEMP%`/AppData +2, no trusted parent +2, webcam/mic in-use by non-allowlisted +3, IOC procname +5. Buckets: **≥8 ALERT, 4–7 REVIEW, <4 INFO.** Microsoft-signed allowlisted → floor toward INFO.

- [ ] **Step 1: Failing test**
```python
# tests/test_score.py
from spyscan.facts import Fact
from spyscan.score import score_fact, bucket

def temp_proc():
    return Fact("processes", "processes::u.exe::u.exe", "process", "u.exe",
                {"from_temp": True, "signed": False, "trusted_ms": False, "is_new": True})
def test_temp_unsigned_new_alerts():
    r = score_fact(temp_proc())
    assert r["score"] >= 8 and bucket(r["score"]) == "ALERT"
    assert "runs from temp" in " ".join(r["reasons"]).lower()
def test_microsoft_signed_allowlisted_is_info():
    f = Fact("autoruns", "autoruns::a::b", "autostart", "X",
             {"verified": True, "trusted_ms": True, "is_new": True})
    r = score_fact(f)
    assert bucket(r["score"]) == "INFO"
def test_bucket_boundaries():
    assert bucket(8) == "ALERT" and bucket(4) == "REVIEW" and bucket(3) == "INFO"
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/score.py
from __future__ import annotations
from spyscan.facts import Fact

def score_fact(f: Fact) -> dict:
    a = f.attrs
    score = 0
    reasons: list[str] = []
    def add(pts, why):
        nonlocal score
        score += pts; reasons.append(f"+{pts} {why}")

    # allowlist: trusted Microsoft signature floors the entity
    if a.get("trusted_ms") or (a.get("verified") and "microsoft" in str(a.get("signer","")).lower()):
        return {"score": 0, "bucket": "INFO", "reasons": ["allowlisted: Microsoft-signed"]}

    if a.get("is_new"):                     add(3, "new since baseline")
    if a.get("signed") is False or a.get("verified") is False:
        add(2, "unsigned / unverified binary")
    if a.get("from_temp"):                  add(2, "runs from temp/appdata")
    if a.get("parent") == "" and f.kind == "process": add(2, "no resolvable parent")
    if a.get("ioc_domain_hit"):             add(3, "connects to known mercenary/C2 domain")
    if a.get("ioc_hash_hit"):               add(5, "file hash matches known implant")
    if a.get("ioc_procname_hit"):           add(5, "process name matches known implant daemon")
    if a.get("in_use_now") and not a.get("trusted_ms"):
        add(3, "webcam/mic in use by non-allowlisted app")
    if a.get("hidden_flag"):                add(1, "hidden-window flag")

    return {"score": score, "bucket": bucket(score), "reasons": reasons}

def bucket(score: int) -> str:
    if score >= 8: return "ALERT"
    if score >= 4: return "REVIEW"
    return "INFO"
```
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: weighted per-entity scoring + buckets + MS allowlist`

---

### Task 13: scan pipeline — diff → enrich → IOC → score

**Files:** Create `src/spyscan/pipeline.py`; Test `tests/test_pipeline.py`
Wire it: collect current facts, mark `is_new` via baseline diff, run IOC matcher (set `ioc_*` attrs), score each, return findings sorted by score desc. Pure given injected collectors/matcher (test with fakes).

- [ ] **Step 1: Failing test**
```python
# tests/test_pipeline.py
from spyscan.facts import Fact
from spyscan.rules.ioc import IOCMatcher
from spyscan.pipeline import build_findings

def test_new_ioc_proc_is_alert():
    base = []
    current = [Fact("processes", "processes::bh::bh", "process", "bh",
                    {"exe": "/x/bh", "parent": "", "from_temp": False, "signed": False})]
    m = IOCMatcher(procnames={"bh"})
    findings = build_findings(base, current, m)
    top = findings[0]
    assert top.bucket == "ALERT"
    assert top.fact.label == "bh"
    assert any("implant daemon" in r for r in top.reasons)
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/pipeline.py
from __future__ import annotations
from spyscan.facts import Fact
from spyscan.finding import Finding
from spyscan.diff import diff_facts
from spyscan.score import score_fact
from spyscan.rules.ioc import IOCMatcher

def build_findings(baseline: list[Fact], current: list[Fact],
                   ioc: IOCMatcher) -> list[Finding]:
    d = diff_facts(baseline, current)
    new_keys = {f.entity_key for f in d["added"]} | {f.entity_key for f in d["changed"]}
    findings = []
    for f in current:
        a = dict(f.attrs)
        a["is_new"] = f.entity_key in new_keys
        # IOC enrichment
        host = a.get("remote_ip") or a.get("image_path") or ""
        if a.get("remote_ip"):
            a["ioc_domain_hit"] = ioc.match_domain(a.get("remote_ip", ""))
        a["ioc_procname_hit"] = ioc.match_proc(f.attrs.get("entry") or f.label.split(" ")[0])
        if a.get("sha256"):
            a["ioc_hash_hit"] = ioc.match_hash(a["sha256"])
        enriched = Fact(f.collector, f.entity_key, f.kind, f.label, a, f.attack_id)
        r = score_fact(enriched)
        # Finding keeps the Fact LIVE (no Fact->dict round-trip); it owns its own
        # JSON via to_dict() and the ALERT|REVIEW policy via is_actionable().
        findings.append(Finding(fact=enriched, score=r["score"],
                                bucket=r["bucket"], reasons=r["reasons"],
                                attack_id=f.attack_id))
    return sorted(findings, key=lambda x: x.score, reverse=True)
```
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: scan pipeline (diff->ioc->score, sorted findings)`

---

### Task 14: JSON + HTML report (PURE)

**Files:** Create `src/spyscan/report/json_out.py`, `src/spyscan/report/html.py`; Test `tests/test_html.py`
Self-contained HTML (inline CSS, `html.escape`, no external dep). Verdict banner from worst bucket; findings table (bucket, score, label, reasons, ATT&CK); honest-limits footer.

- [ ] **Step 1: Failing test**
```python
# tests/test_html.py
from spyscan.facts import Fact
from spyscan.finding import Finding
from spyscan.report.html import render_html
def test_html_has_verdict_and_escapes():
    findings = [Finding(fact=Fact("processes", "processes::bh::bh", "process",
                                  "<b>bh</b>", {}),
                        score=10, bucket="ALERT",
                        reasons=["+5 implant daemon"], attack_id="T1125")]
    html = render_html(findings, meta={"host": "PC", "when": "2026-06-29"})
    assert "ALERT" in html
    assert "&lt;b&gt;bh&lt;/b&gt;" in html          # escaped, not raw tag
    assert "not a kernel EDR" in html.lower() or "clean result" in html.lower()
def test_verdict_clean_when_no_alerts():
    findings = [Finding(fact=Fact("c", "c::x::x", "process", "x", {}),
                        score=1, bucket="INFO", reasons=[], attack_id=None)]
    html = render_html(findings, meta={"host": "PC", "when": "now"})
    assert "No high-risk" in html or "likely clean" in html.lower()
```
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**
```python
# src/spyscan/report/json_out.py
import json
from spyscan.finding import Finding
def render_json(findings: list[Finding], meta: dict) -> str:
    # Each Finding owns its JSON via to_dict() -- one producer of the on-disk shape.
    return json.dumps({"meta": meta,
                       "findings": [f.to_dict() for f in findings]}, indent=2)
```
```python
# src/spyscan/report/html.py
from __future__ import annotations
from html import escape
from spyscan.finding import Finding

_CSS = "body{font:14px system-ui;margin:2rem;background:#0b0f14;color:#dfe7ef}" \
       "h1{margin:0}.v{padding:1rem;border-radius:8px;font-weight:700;margin:1rem 0}" \
       ".ALERT{background:#5a1620;color:#ffd7dd}.REVIEW{background:#5a4416;color:#ffe7b3}" \
       ".INFO{background:#16304a;color:#cfe6ff}table{width:100%;border-collapse:collapse}" \
       "td,th{border-bottom:1px solid #25303c;padding:.4rem;text-align:left;vertical-align:top}" \
       ".foot{margin-top:2rem;color:#8aa;font-size:12px}"

def _verdict(findings):
    # Verdict banner = worst bucket present across ALL findings.
    if any(f.bucket == "ALERT" for f in findings):
        return "ALERT", "Suspicious activity found — review the ALERT rows below."
    if any(f.bucket == "REVIEW" for f in findings):
        return "REVIEW", "Some items warrant a look. No high-confidence spyware signal."
    return "INFO", "No high-risk findings — device likely clean (see limits below)."

def render_html(findings: list[Finding], meta: dict) -> str:
    vb, vmsg = _verdict(findings)
    # Table lists only actionable findings (ALERT + REVIEW), sorted by score desc;
    # INFO is collapsed. is_actionable() is the single owner of that policy.
    shown = sorted((f for f in findings if f.is_actionable()),
                   key=lambda x: x.score, reverse=True)
    rows = []
    for f in shown:
        fact = f.fact
        rows.append(
            f"<tr><td class='{f.bucket}'>{f.bucket} ({f.score})</td>"
            f"<td>{escape(str(fact.label))}</td>"
            f"<td>{escape(str(fact.collector))}</td>"
            f"<td>{escape(', '.join(f.reasons))}</td>"
            f"<td>{escape(str(f.attack_id or ''))}</td></tr>")
    foot = ("This is a usermode scanner/triage tool — <b>not a kernel EDR</b>. "
            "It can miss kernel-hidden or zero-click implants. A clean result is "
            "<b>not</b> proof the device is clean. Local-only; no data left this machine.")
    return (f"<!doctype html><meta charset=utf-8><style>{_CSS}</style>"
            f"<h1>spyscan report</h1><div>{escape(meta.get('host',''))} · "
            f"{escape(meta.get('when',''))}</div>"
            f"<div class='v {vb}'>{vb}: {escape(vmsg)}</div>"
            f"<table><tr><th>Risk</th><th>Entity</th><th>Source</th>"
            f"<th>Why</th><th>ATT&CK</th></tr>{''.join(rows)}</table>"
            f"<p class='foot'>{foot}</p>")
```
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: JSON + self-contained HTML report with honest-limits footer`

---

### Task 15: wire full CLI (`scan` → pipeline → reports) + end-to-end proof

**Files:** Modify `src/spyscan/cli.py`; Test `tests/test_cli_e2e.py`

- [ ] **Step 1: Failing test** (fake collectors via monkeypatch, assert report files written)
```python
# tests/test_cli_e2e.py
from spyscan import cli
from spyscan.facts import Fact

def test_scan_writes_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "DB", tmp_path / "b.db")
    monkeypatch.setattr(cli, "_collect_all",
        lambda: [Fact("processes", "processes::bh::bh", "process", "bh",
                       {"signed": False, "from_temp": True})])
    assert cli.main(["baseline"]) == 0
    rc = cli.main(["scan"])
    assert rc == 0
    assert (tmp_path / "runs" / "last_scan.json").exists()
    assert (tmp_path / "runs" / "last_scan.html").exists()
```
- [ ] **Step 2: Run** → FAIL (cli still Phase-0).
- [ ] **Step 3: Implement** — replace `cmd_scan` to call the pipeline + both reports:
```python
# additions/edits in src/spyscan/cli.py
from datetime import datetime, timezone
import socket
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher
from spyscan.report.json_out import render_json
from spyscan.report.html import render_html

IND = ROOT / "src" / "spyscan" / "rules" / "indicators"

def cmd_scan(args):
    store = BaselineStore(DB)
    base = store.load_baseline()
    if not base:
        print("no baseline yet — run: spyscan baseline"); return 2
    current = _collect_all()
    ioc = IOCMatcher.from_dir(IND)
    findings = build_findings(base, current, ioc)
    meta = {"host": socket.gethostname(),
            "when": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    alerts = [f for f in findings if f.bucket == "ALERT"]
    print(f"findings: {len(findings)}  ALERT: {len(alerts)}  "
          f"REVIEW: {sum(f.bucket == 'REVIEW' for f in findings)}")
    for f in alerts:
        print(f"  [ALERT {f.score}] {f.fact.label} :: {', '.join(f.reasons)}")
    runs = ROOT / "runs"; runs.mkdir(exist_ok=True)
    (runs / "last_scan.json").write_text(render_json(findings, meta), encoding="utf-8")
    (runs / "last_scan.html").write_text(render_html(findings, meta), encoding="utf-8")
    print(f"report: {runs / 'last_scan.html'}")
    return 0
```
- [ ] **Step 4: Run unit + REAL end-to-end**

Run: `.venv/Scripts/python -m pytest -q`  → Expected: all PASS.
Real proof:
```bash
.venv/Scripts/python -m spyscan.cli baseline
.venv/Scripts/python -m spyscan.cli scan
start runs/last_scan.html
```
Expected: report opens, verdict banner shows, honest-limits footer present. Add a fake `HKCU\...\Run` autostart pointing at `%TEMP%\x.exe` + re-baseline-then-scan to confirm it lands as REVIEW/ALERT, then remove it.

- [ ] **Step 5: Commit** `feat: full scan pipeline wired to CLI + JSON/HTML reports`

---

### Task 16: Defender second-opinion (optional enrichment)

**Files:** Create `src/spyscan/enrich/defender.py`; Test `tests/test_defender_parse.py`
Shell out to built-in `MpCmdRun.exe -Scan -ScanType 3 -File <path>` / PS `Get-MpThreat`; `parse()` over output → `{"defender_hit": bool, "threat": str}`. Feed into scoring (+5 if hit). Zero-install everywhere. (Pure parser tested; impure call integration-marked.)

- [ ] Steps mirror Task 10 (test parser with captured strings, implement gather+parse, wire +5 into `score_fact` under `a.get("defender_hit")`, commit).

---

## Self-review (done against the spec)

- **Spec coverage:** threat model → collectors (autoruns/process/netconn/consentstore + services/drivers noted) + IOC list seeded from mercenary brief ✓; three engines → baseline-diff (Task 3/13) + IOC (Task 11) + behavioral scoring (Task 12) ✓; one risk score (Task 12) ✓; on-demand CLI (Task 5/15) ✓; JSON+HTML (Task 14) ✓; local-only + honest-limits footer (Task 14) ✓; Python 3.14 + named libs ✓; MIT-clean (permissive deps only; Sysinternals/Defender shelled, never bundled) ✓.
- **Type consistency:** `Fact`/`make_key` used identically across tasks; `parse(raw)->list[Fact]` contract uniform; `score_fact->{score,bucket,reasons}` and `bucket()` consistent across Tasks 12/13/15.
- **Placeholder scan:** every code step carries runnable code; the only deferred items are explicitly-scoped (services_tasks/drivers as 9b/9c with the stated pattern; Defender Task 16 mirrors Task 10) — not silent gaps.
- **Honest gap flagged:** exact `autorunsc` CSV headers vary by Sysinternals build → Task 4 Step 1 captures the real header before relying on it (parser maps by name, tolerant).

---

## Roadmap beyond this plan (from GROUNDING-BRIEF §6 / ADVANCED-THREAT §2)

- **Phase 2 — rule engines:** scope-limited `yara-python` over flagged binaries; Sigma-subset matcher over Sysmon events; live IOC feed auto-update (abuse.ch ThreatFox/URLhaus with Auth-Key + STIX2 from Amnesty repo).
- **Phase 3 — live + correlation:** lightweight ETW/WMI watcher (process-create, net, registry-autostart writes) → rolling event store; time-window correlation so weak signals stack into one scored incident.
- **Phase 4 — cross-device:** factor the engine into a portable core; **TinyCheck/PiRogue-style** network appliance (Zeek+Suricata over pcap) for phones/IoT; **MVT** invoked as a subprocess for mobile forensic IOC matching (do NOT reimplement).
- **Phase 5 — intel + guarded response:** ATT&CK coverage map; canary-token tripwire capability (detect the unknown implant by behavior); human-confirmed quarantine/disable-autostart.

> **Honest limit, restated:** usermode Python can't match kernel-callback EDRs for tamper-resistance; advanced/zero-click implants can hide from usermode enumeration. Ship as scanner/triage + pair with network-side + forensic layers for the hard threats.
