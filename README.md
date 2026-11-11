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
| `canary` | honeyfile decoys that were changed, moved or deleted, or **read** once access auditing is on (+8 → ALERT, never silenced; see [Canary tripwires](#canary-tripwires-decoy-files)) | T1530 |

Three detection engines add points to **one score** per entity (each signal adds a fixed number of points; there is no cap):
1. **baseline-diff** — what changed since your clean snapshot,
2. **signature/IOC** — known mercenary-spyware domains (matched against the Windows DNS cache: a connection to an IP resolved from a listed domain, or a cached lookup of one) + implant daemon names (Pegasus/Predator/Candiru, cited from Amnesty/Citizen Lab; most target phones, so on Windows they rarely fire), Authenticode signing, Windows Defender second-opinion,
3. **behavioral** — temp-path / unsigned / no-parent / hidden-window or encoded PowerShell / live cam-mic / tripped decoys.

Buckets: **ALERT ≥8 · REVIEW 4–7 · INFO <4.** A verified Microsoft signature floors a finding to INFO, with four exceptions: the signer must be Microsoft's own (not the *Hardware Compatibility Publisher* that signs third-party drivers); the entry must name its program, and that program must sit in the Windows, Program Files or Defender folders (a Microsoft program installed per user under AppData, such as OneDrive or Teams, is scored on its other signals, so a new one shows as REVIEW until it is in your baseline); the entry must run only itself (a program that can run other code, such as PowerShell, cmd or rundll32, given arguments, or a launch string reaching into temp/AppData, is not floored); and a known-bad signal (Defender hit / IOC name / tripped decoy) always overrides the floor (no signed-malware bypass). A new persistence entry (autostart, service, task, driver) scores +4, so it reaches REVIEW on its own; a new process or connection scores +3. Loopback/ephemeral connections are floored to benign so the report doesn't drown in churn.

---

## If you think someone is watching you

Your safety matters more than any scan result. Software that watches you can also show the person behind it that you scanned, searched for help, or removed something, and removing it can make things more dangerous.

- **Document first, remove later.** Keep the report (`runs\last_scan.html` and `.json`), take photos of what you find, and note the dates. Do not delete anything until you have a plan.
- **Plan from a device they have never had access to**, such as a trusted friend's phone or a library computer.
- **Get help.** The [Coalition Against Stalkerware](https://stopstalkerware.org/) lists support organisations by country. For example: in the US, the National Domestic Violence Hotline (1-800-799-7233); in the UK, the National Domestic Abuse Helpline (0808 2000 247). In danger, call your local emergency number.
- **spyscan leaves traces.** It never removes anything, but its folder, its report and any decoy files can be seen by someone who uses this PC. `spyscan canary clear` removes the decoys.

---

## Quick start

### Option A — packaged app (no Python needed)

1. Download `SpyScan-v0.2.0-win64.zip` (one-folder build) or the single-file `SpyScan.exe`
   from [Releases](https://github.com/NAJEMWEHBE/spyscan/releases).
2. Verify it against `SHA256SUMS` from the same release (or check its build provenance with
   `gh attestation verify SpyScan.exe --repo NAJEMWEHBE/spyscan`):

   ```powershell
   Get-FileHash .\SpyScan-v0.2.0-win64.zip -Algorithm SHA256
   ```

3. Unzip and run `SpyScan\SpyScan.exe` (or run the single-file `SpyScan.exe` directly). The exe is currently **unsigned**, so SmartScreen will warn
   (“More info → Run anyway”) — that is exactly why the hashes are published, and Option B
   exists if you'd rather build from source. You can also cross-check the exe on
   [VirusTotal](https://www.virustotal.com/) (search its SHA-256);
   a few heuristic engines may flag any unsigned PyInstaller one-file exe (the
   self-extracting packaging resembles how some malware bundles itself — a known
   false-positive source).
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

### Already suspect this PC? Take a first look instead

A baseline taken on a PC that is already being watched would record the spyware as "known-good". If you think the PC is compromised **now**, do not baseline it; run a first look:

```powershell
.\.venv\Scripts\spyscan triage      # or the app's "First look (no baseline)" button
```

It scores what is there now on absolute signals: every autostart, service, scheduled task and driver gets a signature check; one that is not proven Microsoft-signed, or is Microsoft-signed but refused the floor (its reason line says why), scores +2, and climbs to REVIEW or ALERT only with a second signal (unsigned, runs from temp/AppData, a script host such as PowerShell or rundll32 launching a payload from a user folder or the web, a known-bad indicator). A signed vendor tool alone stays INFO. It never writes `baseline.db`. Expect more to review than a baseline scan, and read the [safety notes](#if-you-think-someone-is-watching-you) first.

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

**Releases** are built by `.github/workflows/release.yml` on GitHub's Windows runner, from the tagged commit only (pushing a tag like `v0.1.1` that matches `pyproject.toml`). It runs the tests, builds both forms, checks the bundled allowlist is the repo's, writes `SHA256SUMS`, records signed build provenance, and opens a **draft** release for a maintainer to publish. To check a download came from that workflow: `gh attestation verify SpyScan.exe --repo NAJEMWEHBE/spyscan`.

The window opens via a native [pywebview](https://pywebview.flowrt.dev/) WebView2 frame (it falls back to your default browser if that runtime is missing). It shows:

- a **Scan now** button and a **Set baseline (trusted machine)** button,
- a **FINDINGS** table (RISK / ENTITY / SOURCE / WHY / ATT&CK) of the ALERT + REVIEW items, with a link to the full HTML report,
- a **BASELINE** panel (exists / fact count) and an **ALLOWLIST** panel (active rule counts + file path).

The packaged app keeps its writable state (`baseline.db`, `runs\`) **next to the executable**, while the bundled read-only resources are served from inside the build. The local server binds `127.0.0.1` only; set `SPYSCAN_PORT` to pin a fixed port (otherwise a free one is chosen and written to `spyscan_url.txt` next to the exe).

**Reading results:** ALERT = look now. REVIEW = worth a glance. A finding shows *why* it scored (e.g. `+4 new persistence entry since baseline, +2 unsigned / unverified binary, +3 runs from temp/appdata`). You decide — the tool surfaces, it does not convict. Build an allowlist for your known-good software to quiet recurring benign hits (e.g. your own dev interpreters).

### Canary tripwires (decoy files)

```powershell
spyscan canary deploy        # plant decoy files (Desktop, Documents, app canaries\)
spyscan canary status        # which decoys were touched (exit code 1 if any)
spyscan canary audit-setup   # print the admin commands that let a scan see a READ
spyscan canary clear         # remove every decoy and the state file
```

Out of the box a decoy trips when it is **changed, moved or deleted**: its content hash, size or modified time differ from what was planted. A program that only **reads or copies** a decoy (the actual theft) changes none of those, and Windows does not keep last-access times by default, so **a read alone is not seen until you turn on access auditing**. `spyscan canary audit-setup` prints the commands for that; it never runs them. Run them once in an elevated PowerShell, and again after each new `deploy`. From then on a read, copy or edit by any other program is logged as Security event 4663, and the next scan raises an ALERT naming that program. spyscan's own check, Microsoft Defender and Windows Search are ignored (by exact name, inside their real install folders only). Reading the Security log needs admin, so run the scan elevated to see reads. Cloud sync tools (OneDrive, Dropbox) read new files too and show up by name.

### Allowlisting your own software

Known-good software (your own dev `python.exe`/`bun.exe` from a venv, a signed vendor tool) can trip the temp/unsigned/new heuristics. The allowlist floors a matched finding to **INFO/0** so it stops alarming — **but a known-bad signal (Defender hit / IOC procname) always overrides it**, so you can never accidentally hide real malware.

The file lives at **`config/allowlist.json`** (shipped, edit in place). Run `spyscan allowlist` to print its path + current rule counts. Four rule types:

| Rule | Matches |
|---|---|
| `path_globs` | `fnmatch` over a finding's exe / image path, case-insensitive (use `\\` in JSON, e.g. `"c:\\tools\\myapp\\*"`) |
| `signers` | case-insensitive **substring** of the Authenticode signer subject (e.g. your code-signing org) |
| `sha256` | exact file hash (also tested against a fact's `md5`) |
| `entity_keys` | exact namespaced finding key (e.g. `processes::name::exe`) |

The shipped default is **empty**: a default rule applies on every user's PC, and a broad one becomes a hiding place. When you run spyscan from source inside a venv, it quiets only that venv's own `Scripts` folder, matched by absolute path at run time. Everything else — your Python installs, dev tools, vendor software — is yours to add; spyscan does not pre-quiet paths it can't know are yours. Keep it **tight** — never allowlist a broad directory like all of `AppData` or `Temp`, or you blind the detector. `scan` prints `allowlisted: N` so you always see how many findings were quieted.

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
.\.venv\Scripts\python -m pytest -q   # integration tests (real OS) are skipped by default
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
