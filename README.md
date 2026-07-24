# spyscan — personal spyware / surveillance awareness scanner

**Defensive tool. Answers one question: _is anything spying on this device?_** Local-only, no telemetry, nothing leaves your machine. A scanner/triage tool — **not** a kernel EDR or antivirus replacement.

PC (Windows) first; cross-device (network appliance + mobile forensics) is the roadmap.

---

## What it does

Snapshots a known-good machine, then on later scans flags what is **NEW / suspicious** across eight signal sources, scores each finding, and writes a verdict report.

| Collector | Catches | ATT&CK |
|---|---|---|
| `autostart_native` | persistence, **shipped default**: Run/RunOnce keys, Startup folders, Winlogon Shell/Userinit, WMI event consumers | T1547.001 / T1547.004 / T1546.003 |
| `autoruns` (Sysinternals) | the fuller ASEP sweep (63 populated locations on the test machine, vs the default build's 6) — **only if you install autorunsc yourself** (see [Autostart coverage](#autostart-coverage-what-it-checks-and-what-it-does-not)) | T1547.001 |
| `processes` | binaries from `%TEMP%`/AppData, no trusted parent, hidden | — |
| `netconns` | remote endpoints + owning process, listening ports | T1071 |
| `consentstore` | **webcam/mic in use right now** (registry `LastUsedTimeStop=0`) | T1125 / T1123 |
| `services_tasks` | new services + scheduled tasks (path, run-as) | T1543.003 / T1053.005 |
| `drivers` | loaded kernel drivers | T1014 |
| `canary` | tripped honeyfile decoys (+8 → ALERT, never silenced) | T1530 |

Three detection engines feed **one 0–100 score** per entity:
1. **baseline-diff** — what changed since your clean snapshot,
2. **signature/IOC** — known mercenary-spyware domains + implant daemon names (Pegasus/Predator/Candiru, cited from Amnesty/Citizen Lab), Authenticode signing, Windows Defender second-opinion,
3. **behavioral** — temp-path / unsigned / no-parent / beaconing / live cam-mic.

Buckets: **ALERT ≥8 · REVIEW 4–7 · INFO <4.** Microsoft-signed is allowlisted to INFO — **unless** a known-bad signal (Defender hit / IOC name) is present, which always overrides the allowlist (no signed-malware bypass). Loopback/ephemeral connections are floored to benign so the report doesn't drown in churn.

---

## Quick start

### Option A — packaged app (no Python needed)

1. Download `SpyScan-v0.1.0-win64.zip` from [Releases](https://github.com/NAJEMWEHBE/spyscan/releases).
2. Verify it against `SHA256SUMS.txt` from the same release:

   ```powershell
   Get-FileHash .\SpyScan-v0.1.0-win64.zip -Algorithm SHA256
   ```

3. Unzip and run `SpyScan.exe`. The exe is currently **unsigned**, so SmartScreen will warn
   (“More info → Run anyway”) — that is exactly why the hashes are published, and Option B
   exists if you'd rather build from source.
4. In the app: **Set baseline** on a machine you trust is clean; later, **Scan now**.

### Option B — from source (CLI)

```powershell
git clone https://github.com/NAJEMWEHBE/spyscan.git
cd spyscan
python -m venv .venv          # Python 3.13+
.\.venv\Scripts\pip install -e .

# 1. Take a baseline — DO THIS ON A MACHINE YOU TRUST IS CLEAN
.\.venv\Scripts\spyscan baseline

# 2. Later, scan for what changed / looks like spying
.\.venv\Scripts\spyscan scan

# 3. Open the report
start runs\last_scan.html
```

- `runs\last_scan.html` — human report: verdict banner, ALERT/REVIEW table with the *evidence* for each finding + ATT&CK tag, honest-limits footer. (INFO items are counted, not listed.)
- `runs\last_scan.json` — full machine-readable findings (all buckets) — consumed by the standalone app UI.

### Standalone app

Same engine, in a native window — no terminal needed.

**In dev** (from the repo):

```powershell
.\.venv\Scripts\python -m spyscan.cli app   # or: spyscan app  (installed)
```

**As a packaged executable** (self-contained: bundles the UI, IOC lists, and allowlist — **not** autorunsc, see below):

```powershell
# Build it (one-folder, recommended)
.\.venv\Scripts\pyinstaller spyscan.spec --noconfirm
# Then double-click dist\SpyScan\SpyScan.exe  (or run it)
```

A one-file build is also supported (`$env:SPYSCAN_ONEFILE=1; .\.venv\Scripts\pyinstaller spyscan.spec --noconfirm` → `dist\SpyScan.exe`); the one-folder build starts faster and is the recommended ship.

The window opens via a native [pywebview](https://pywebview.flowrt.dev/) WebView2 frame (it falls back to your default browser if that runtime is missing). It shows:

- a **Scan now** button and a **Set baseline (trusted machine)** button,
- a **FINDINGS** table (RISK / ENTITY / SOURCE / WHY / ATT&CK) of the ALERT + REVIEW items, with a link to the full HTML report,
- a **BASELINE** panel (exists / fact count) and an **ALLOWLIST** panel (active rule counts + file path).

The packaged app keeps its writable state (`baseline.db`, `runs\`) **next to the executable**, while the bundled read-only resources are served from inside the build. The local server binds `127.0.0.1` only; set `SPYSCAN_PORT` to pin a fixed port (otherwise a free one is chosen and written to `spyscan_url.txt` next to the exe).

**Reading results:** ALERT = look now. REVIEW = worth a glance. A finding shows *why* it scored (e.g. `+3 new since baseline, +2 unsigned, +3 runs from temp`). You decide — the tool surfaces, it does not convict. Build an allowlist for your known-good software to quiet recurring benign hits (e.g. your own dev interpreters).

### Allowlisting your own software

Known-good software (your own dev `python.exe`/`bun.exe` from a venv, a signed vendor tool) can trip the temp/unsigned/new heuristics. The allowlist floors a matched finding to **INFO/0** so it stops alarming — **but a known-bad signal (Defender hit / IOC procname) always overrides it**, so you can never accidentally hide real malware.

The file lives at **`config/allowlist.json`** (shipped, edit in place). Run `spyscan allowlist` to print its path + current rule counts. Four rule types:

| Rule | Matches |
|---|---|
| `path_globs` | `fnmatch` over a finding's exe / image path, case-insensitive (use `\\` in JSON, e.g. `"*\\.venv\\scripts\\*"`) |
| `signers` | case-insensitive **substring** of the Authenticode signer subject (e.g. your code-signing org) |
| `sha256` | exact file hash (also tested against a fact's `md5`) |
| `entity_keys` | exact namespaced finding key (e.g. `processes::name::exe`) |

The shipped default seeds **only** your local dev interpreters (`.venv\Scripts`, the spy-detector venv, the `C:\Python314` install, uv-managed python + tools). Keep it **tight** — never allowlist a broad directory like all of `AppData` or `Temp`, or you blind the detector. `scan` prints `allowlisted: N` so you always see how many findings were quieted.

---

## Autostart coverage: what it checks, and what it does not

**The shipped build does not include Sysinternals `autorunsc`.** Its license forbids
redistribution ("you may not publish the software for others to copy" / "transfer the
software … to any third party") with no free/non-commercial carve-out, so no spyscan
download can legally carry it. Private use is fine — which is why *you* may install it.

Autostart coverage therefore ships as `autostart_native`, a pure-Python collector. It is a
**deliberate subset** of autorunsc's sweep, and the gap is real: on the Windows 11 test
machine this was measured on, `autorunsc -a *` reported **63 autostart locations** and the
default build reads **6** of them. That is a coverage difference you should know about
before you trust a clean result.

**What the default build reads**

| Location | Detail |
|---|---|
| Run / RunOnce / RunServices / RunServicesOnce | HKLM (native **and** WOW64 32-bit views) + HKCU (native only — `HKCU\SOFTWARE` is [shared, not redirected](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)) |
| Startup folders | per-user `%APPDATA%` + common `%ProgramData%` |
| Winlogon | `Shell` and `Userinit` values only |
| WMI event consumers | `root/subscription` `CommandLineEventConsumer` + `ActiveScriptEventConsumer` |
| Services / scheduled tasks / drivers | via `services_tasks` and `drivers`, which run in **every** configuration and include *disabled* entries (autorunsc reports those too, tagged `Enabled=disabled`) |

**What it does not read — every one of these is somewhere an implant can hide from the
default build**

| Not checked | Why it matters |
|---|---|
| `BootExecute` | native binary run by `smss.exe` at boot, before the Win32 subsystem or any security service starts |
| `AppInit_DLLs` | with Secure Boot off, loaded by `user32.dll` into nearly every interactive process |
| Image File Execution Options `Debugger` | silently redirects any exe launch, at SYSTEM level for a service image |
| Credential providers, `Winlogon\GpExtensions` | a rogue credential provider participates in collecting your password at every logon |
| Print monitor / provider DLLs | loaded into `spoolsv.exe` as SYSTEM at every boot (T1547.010) |
| Browser Helper Objects, shell extensions, codecs, Winsock LSPs | DLLs loaded into Explorer, browsers, or any networking process |
| LSA authentication / notification packages | loaded into `lsass.exe`; a notification package is a password filter that sees every plaintext password change |
| `Active Setup`, `SafeBoot\AlternateShell`, `IconServiceLib`, `KnownDLLs` | further logon/boot ASEPs that were populated on the test machine |
| Network / RDP / Office / IE providers and shell service objects | `SecurityProviders`, `NetworkProvider\Order`, `rdpwd\StartupPrograms`, `Protocols\Filter`+`Handler`, Outlook `Addins`, `ShellServiceObjects`, `ShellIconOverlayIdentifiers`, `UrlSearchHooks` — all populated on the test machine |

Two related blind spots outside the autostart list, for the same reason (spyscan records what
the OS API hands back, and does not resolve it further):

- **svchost-hosted services** record only `svchost.exe -k <group> -p` — the per-service
  `Parameters\ServiceDll` under `HKLM\SYSTEM\CurrentControlSet\Services` is never read, so
  swapping that DLL changes nothing spyscan diffs.
- **Scheduled tasks** are enumerated completely, but `schtasks` reports many actions as
  `"COM handler"` rather than a path, and task facts are not signature/hash-enriched — so for
  those tasks the executed code is never resolved and the temp-path signal cannot fire.

**Want the full sweep?** Install Sysinternals Autoruns yourself and put `autorunsc64.exe` on
your `PATH`, in `C:\Program Files\Sysinternals`, or in a `tools\` folder next to `SpyScan.exe`.
spyscan picks it up on the **next scan** — no restart needed, all three locations behave the
same — runs the full `-a *` sweep, and `autostart_native` steps aside, so the registry /
Startup / Winlogon / WMI entries are not reported twice. Services, drivers and scheduled tasks
are still reported by *both* autorunsc and the `services_tasks` / `drivers` collectors, so
expect those to appear from two sources.

> Scope caveat: the location counts above were produced by running the vendor binary on **one**
> Windows 11 machine. They are verified lower bounds on each category, not a proven-exhaustive
> list — a category that happens to be empty on that box emits no rows. The table says what
> spyscan *does not read*; it does not claim every listed technique still works on current
> Windows.

---

## Honest limits

- **Usermode scanner, not a kernel EDR.** Advanced/zero-click implants can hide from usermode enumeration. A clean result is **not** proof the device is clean.
- **Autostart coverage is a subset**, not the full ASEP surface — see [Autostart coverage](#autostart-coverage-what-it-checks-and-what-it-does-not) for exactly which locations go unchecked and how to close the gap.
- IOC feeds go stale fast (actors rotate infra) — that's why baseline-diff + behavior carry the weight, not signatures alone.
- Detects on devices you **own/control**; this is defensive, not for surveilling others.

---

## Tests

```powershell
.\.venv\Scripts\python -m pytest -q   # 263 passing
```
Pure logic (schema, diff, score, parsers) is fixture-unit-tested; OS-touching collectors are integration-marked.

---

## Roadmap (built = Phase 0+1)

- **Phase 2** — network-side appliance (TinyCheck/PiRogue: Zeek+Suricata over a monitored hotspot) → catches **any device** (phones/IoT) with no install.
- **Phase 3** — mobile forensics via Amnesty **MVT** (iOS/Android implant IOC matching), invoked as a subprocess.
- **Phase 4** — live ETW/WMI watcher + event correlation; in-app live dashboard.
- **Phase 5** — ~~canary-token tripwires~~ **BUILT**: canary-token tripwires catch the unknown implant by behavior (a tripped decoy scores +8 → ALERT and is never silenced by an allowlist/MS floor; see `canary_audit.py`). Guarded response remains roadmap.
- **Near-term tuning** — ~~user allowlist~~ **BUILT** (see [Allowlisting your own software](#allowlisting-your-own-software)); still open: fresh-baseline helper, populate `verified` for process facts, YARA over flagged binaries, live abuse.ch IOC feed.

See `docs/` for the full grounding brief, advanced-threat brief, design decisions, and build plan (all cited).

---

## License

[MIT](LICENSE).

---

_Defensive security tool. Built to make you **aware**, not to spy._
