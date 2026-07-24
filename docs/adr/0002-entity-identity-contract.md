# ADR 0002 — the entity-identity contract (key = stable identity; observations don't diff)

- **Status:** Accepted — 2026-07-24 (grilled via option-picker: `Fact.observed` dict; strict
  volatile→observed litmus; drop pid-0 TIME_WAIT + `(unowned)` sentinel; reshape keys with
  measured compat, no migration)
- **Relates to:** SPYSCAN-COLLECTOR-SWEEP-FINDINGS-2026-07-24 (15 confirmed defects, 0 collectors
  clean); the services_tasks per-trigger fold and the autostart_native WOW64 fix are the two
  pre-existing worked examples this contract generalizes.

## Context

Every collector invented `entity_key` and its diffed `attrs` ad hoc. A 22-agent sweep confirmed
15 defects across all 7 collectors, and every one is the same disease in one of four costumes:

1. **Key too coarse** → distinct real entities collide (296 process facts → 94 keys; HKCU/HKLM
   consentstore rows on one key; autoruns row families) → implants mask into existing keys,
   `store.py`'s PRIMARY KEY silently drops rows, diff survivors are enumeration-order lottery.
2. **Key too fine** → one real entity re-keys on routine change (full DriverStore versioned path
   in driver keys) → every driver update mints a phantom added + "possible implant cleanup"
   removed pair.
3. **Volatile observations in diffed attrs** (pid, ephemeral ports, Running/Stopped, atime that
   our own scan advances) → phantom `changed` → `is_new` +3 noise; a tripped canary can never
   settle.
4. **Placeholders/containers minted as entities** (`NonPackaged` container-as-app, 64 autorunsc
   location headers, pid-0 sockets keyed as `netconns::::ip:port`) → junk facts with false
   penalty signals, and the real population beneath a container (Win32 webcam/mic apps!) never
   enumerated.

`diff.py` and `store.py` are correct and stay dumb — every defect is upstream of them.

## Decision — five rules every collector must obey

**Definition.** An *entity* is one real-world persistence/activity thing as a user would point
at it: one autostart component, one driver service, one process image, one process↔remote-
endpoint relationship, one app's device-usage record in one hive, one canary file.

### Rule 1 — the key is the entity's stable identity, nothing else

`entity_key` is built only from fields that survive reboot, re-enumeration, and routine
vendor updates: names, hives/scopes, full *install* paths, launch strings. Never: pid, ephemeral
port, timestamp, runtime state, or a *versioned* path segment (DriverStore `*.inf_amd64_<hash>`
dirs). **Litmus: two scans with zero attacker/user action in between must yield the identical
key set.**

### Rule 2 — exactly one Fact per entity per scan

- **Fold** when the source emits many rows for one entity (schtasks per-trigger rows;
  per-socket rows for one process↔endpoint; per-instance rows for one process image).
  Folded multiplicity becomes a count/sorted-set, not N facts.
- **Split** when one row carries several entities (Winlogon `Userinit`'s comma list → one fact
  per component, each with its own image_path and key).
- **Never mint containers/headers as entities** (autorunsc location-header rows, ConsentStore
  `NonPackaged` container): enumerate their children as the entities, or skip them.
- Within one scan a collector's keys MUST be unique. A collision is a collector bug — store's
  `INSERT OR REPLACE` and diff's dict-builds silently last-win, so it never crashes; it lies.

### Rule 3 — attrs are alertable state; observations go in `Fact.observed`

`attrs` participate in diff equality, so **every attr change must mean "someone did something"**
(config changed, a new trigger appeared, the mic was actually used). Anything that can change
with zero attacker/user action — reboot, enumeration order, demand-start/stop, TIME_WAIT churn,
*our own scan reading a file* — is an observation, not an attr.

Mechanism: `Fact` gains an `observed: dict` field. `diff.py` is untouched — it already compares
only `attrs`, so `observed` is invisible to it by construction. `observed` IS persisted in the
baseline, MAY feed labels/scoring/reports, NEVER feeds diff.

| goes in `attrs` (diffed) | goes in `observed` (never diffed) |
|---|---|
| image/install path, launch string | pid, parent pid, pid lists |
| signer/verified, start_mode, trigger list + count | instance_count, conn_count |
| capability last_start/last_stop (change = app really used the mic) | ephemeral local ports |
| canary content-hash/mtime/size tamper evidence | Running/Stopped state, atime evidence |

### Rule 4 — placeholders are explicit sentinels, never data

Unknown owner → `"(unowned)"` in key/label/attrs, consistently. Unknown signer →
`verified=None` (unknown), never `False` (a determinate penalty). Empty string is never an
identity component and never a scoreable value.

### Rule 5 — key changes land with a measured baseline-compat note

Any fix that reshapes keys is landed the way the services_tasks fold was: run against the real
`baseline.db`, record which keys change, what fires once after upgrade (and in which bucket),
and whether a re-baseline is needed. "Probably fine" is not a measurement.

## The 15 defects mapped to the rules (fix order = product impact)

| # | collector | fix under the contract | rules |
|---|---|---|---|
| 1 | consentstore | recurse into `NonPackaged`, one fact per leaf exe (decode `#`→`\`), drop the container fact; add `scope` (hive) to the key | 2, 1 |
| 2 | processes | key = (name, full exe path); fold instances; pid/parent/cmdline-set/instance_count → `observed` | 1, 2, 3 |
| 3 | autostart_native | split Winlogon Shell/Userinit multi-program values into one fact per component | 2 |
| 4 | autoruns | skip location-header rows (no entry AND no image AND no launch); empty signer → `verified=None`; add launch_string to the key | 2, 4, 1 |
| 5 | netconns | fold to one fact per (process, remote endpoint); local ports/pids → `observed`; pid-0 → `"(unowned)"` sentinel (TIME_WAIT pid-0 rows dropped in gather) | 2, 3, 4 |
| 6 | drivers | key = (name, module) — module names are unique SCM names; full path stays an attr; `state`/`status` → `observed` | 1, 3 |
| 7 | canary | atime evidence → `observed` (tripped canary settles after re-baseline); regroup 4663 events case-insensitively to match the parser | 3, 4 |
| 8 | startup folders | resolve `.lnk` targets in gather; target = image_path (from_temp from target); lnk container path = launch/location detail | 4 |

## Alternatives considered

- **Declared non-diffed attr names, filtered in `diff.py`.** Keeps one dict but makes diff
  policy-aware per collector — exactly the "diff.py stays dumb" line we refuse to cross, and
  the declaration lives far from the data it governs. Rejected.
- **Volatile data in `label` only.** Loses the data for reports/scoring (e.g. conn_count,
  accessed_by) and turns labels into parsing targets. Rejected.
- **15 point fixes without a contract.** Re-improvises identity a 16th time the next time a
  collector is added. Rejected — the sweep's whole finding is that the disease is systemic.

## Measured results (2026-07-24, this box, real baseline.db — Rule 5 record)

All 15 sweep defects fixed against the contract in one pass (plus services_tasks
runtime state/last_run_time, same disease found during the fix sweep). Live invariant
check across every collector: **2,824 facts, 0 key collisions** (was 81× svchost on one
key, 91 facts per netconns endpoint, 20→19 consentstore rows silently dropped).

| collector | facts→keys after fix | headline win (measured live) |
|---|---|---|
| consentstore | 36→36 (was 20→19) | 19 Win32 apps under NonPackaged now enumerated (incl. rundll32.exe, HKLM svchost.exe) — the headline webcam/mic feature sees Win32 at all |
| processes | 257 rows→88 facts | temp-path svchost.exe implant now mints its own key: **8 ALERT** (was masked, never `added`) |
| autostart_native | — | Userinit append-hijack payload mints as `added` (was attrs-only `changed`, INFO); real .lnk target resolved (WScript.Shell), from_temp inversion gone |
| autoruns | 1610→1610 (was 1678→1669) | 64 header rows gone; verified None(33)/False(9) honest; launch_string in key kills the row-family masking (ALERT demotion) |
| netconns | 110 rows→88 facts | pid-0 TIME_WAIT dropped at gather; `(unowned)`/`(unresolved)` sentinels; x20 fold on one endpoint |
| drivers | 466→466 | driver update = `changed` on stable key, not added+"implant cleanup" pair; state flips diff-silent |
| canary | — | tripped canary settles (atime pinned back after our own hash read + atime/audit evidence in `observed`); 4663 attribution survives casing |
| services_tasks | 528→528 | last_run_time/Status churn out of diff (was firing every scan) |

End-to-end vs the OLD baseline (one-time upgrade view): 116 REVIEW / 4,843 INFO / 0 ALERT
— the key-reshape burst, dominated by the old baseline's own junk attrs on the removed
side. **Re-baseline immediately after upgrading** and it clears: steady-state after a
fresh baseline measures **1 REVIEW / 0 ALERT / 2,823 INFO** (the 1 is a live unsigned
session tool, genuine borderline).

## Consequences

- `Fact` grows `observed` (default `{}`); `from_dict` tolerates old baselines (missing key →
  empty). `diff.py`/`store.py` byte-identical. `score_fact` may read `f.observed` where a
  signal is observation-based (`in_use_now` stays an attr-derived live signal per collector).
- Collectors get a shared invariant check (test-level): unique keys per scan, no empty key parts.
- One-time diff burst per collector when keys reshape — measured and recorded per Rule 5
  before each lands.
