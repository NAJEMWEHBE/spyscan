# Grounding Brief — Personal Spyware / Surveillance Detector (PC-first, then any device)

Merged from 6 research dumps. Cited to primary sources (full URLs in §8). Verified-vs-unverified flagged. Engineering-actionable.

**One-line thesis:** A solo-dev Windows detector should be a **local-only baseline-then-diff scanner** (snapshot autostarts/processes/connections/drivers, alert on NEW + suspicious), enriched with signature/reputation lookups and a few high-signal behavioral checks — orchestrating Sysinternals + Defender + osquery as the data plane rather than reinventing kernel collection. Cross-device reach comes from the **TinyCheck** network-side model (any Wi-Fi device, agentless) and **MVT** (mobile forensic IOC matching). It is a **scanner/triage tool, not a kernel EDR** — be honest about that limit.

---

## 1. Threat model overview — technique → signal → data source

How spying actually happens on a PC, mapped to MITRE ATT&CK. Each row = the attacker technique, the observable signal a detector can catch, and the Windows data source/API/log/registry that yields it.

| # | Technique (ATT&CK ID) | Observable SIGNAL | Data source / API / log / registry |
|---|---|---|---|
| 1 | **User-mode keylogger** — Input Capture (T1056.001) | Non-UI process registering keyboard hooks / polling keys; growing `*.log`/`*.dat` in `%APPDATA%`/`%TEMP%` | Win32k ETW provider `{8c416c79-...}` EID **1002** `FilterType=0xD` (WH_KEYBOARD_LL); EID **1001** `Flags=256` (RIDEV_INPUTSINK raw input); EID **1003** background `GetAsyncKeyState` polling |
| 2 | **Kernel keylogger** — keyboard filter driver in kbdclass stack | Unsigned/unusual driver filtering Kbdclass; bypasses user-mode API watch | Sysmon **EID 6** (DriverLoad), **EID 7045** service install, `HKLM\SYSTEM\CurrentControlSet\Services\*` Type=1 |
| 3 | **RAT** (DarkComet/njRAT/Quasar/AsyncRAT/Remcos) | Persistent autostart + long-lived outbound socket from unknown proc; one process loading camera+audio+GDI capture; `cmd`/`powershell` child from non-shell parent | Sysmon EID 1 (lineage) + EID 3 (net) + autoruns surface (§3) |
| 4 | **Infostealer** — Steal Web Session Cookie (T1539), Creds from Browsers (T1555.003) | Short-lived non-browser proc reading browser SQLite (`Cookies`, `Login Data`, `Web Data`, `Local State`); foreign proc injecting `chrome.exe` to invoke ABE COM decrypt; one burst of Telegram/HTTP exfil then exit | File reads of `…\User Data\…`; Sysmon EID 10/8 (injection); EID 22 (DNS) / EID 3 (net) |
| 5 | **Stalkerware / "monitoring" agents** (mSpy/FlexiSpy/Hoverwatch) | Hidden no-UI process, autostart, periodic upload to known vendor domain; screenshot/keylog file churn | Autoruns + ECHAP stalkerware-indicators IOC lists; AV "not-a-virus"/riskware tag |
| 6 | **Screen Capture (T1113)** | Non-graphics proc calling `BitBlt`/`GetDC(NULL)`/`CopyFromScreen`; timestamped images in temp | API monitoring; EID 11 (image file create) |
| 7 | **Clipboard Data (T1115)** | Background proc polling clipboard; `Get-Clipboard` in PS logs; wallet-address swaps | `OpenClipboard`/`GetClipboardData` API; PowerShell EID 4104 |
| 8 | **Webcam hijack — Video Capture (T1125)** | Process outside allowlist opening capture device; video files written then exfil | **CapabilityAccessManager ConsentStore** registry (§2.4) — `LastUsedTimeStop=0` = in use NOW |
| 9 | **Mic hijack — Audio Capture (T1123)** | Same as above for microphone | ConsentStore `\microphone`; MITRE detection strategy = allowlist of authorized procs (DET0221) |
| 10 | **Abused legit remote tools — Remote Access Software (T1219)** (AnyDesk/ScreenConnect/TeamViewer/Atera) | Silent RMM install + autostart + unattended-access password + disabled updates; outbound to vendor relay | EID **7045** new service; Programs-and-Features registry; vendor logs (§8 remote indicators) |
| 11 | **RDP (T1021.001)** | `fDenyTSConnections=0` flip; inbound logon | Registry; Security **4624 LogonType 10**, **4778/4779**; TerminalServices logs EID 1149/21-25 |
| 12 | **Hidden VNC (hVNC)** — covert 2nd desktop (TrickBot/LOBSHOT) | `CreateDesktopW`/`SetThreadDesktop`; second `explorer.exe` on non-Default desktop | API monitoring; Microsoft Defender "suspicious processes on hidden desktops" detection |
| 13 | **Persistence — Run keys (T1547.001)** | New value pointing to temp/appdata or unsigned binary (~28% of Win intrusions — see §7 UNVERIFIED) | `HKCU/HKLM\…\CurrentVersion\Run`,`RunOnce`; Sysmon EID **12/13** |
| 14 | **Persistence — Startup folder (T1547.001)** | New `.lnk`/script | `…\Start Menu\Programs\Startup`; Sysmon EID 11 |
| 15 | **Persistence — Scheduled Task (T1053.005)** | Task running LOLBin at logon/interval | `\System32\Tasks\` XML; Security **4698** |
| 16 | **Persistence — Service (T1543.003)** | New service, user-writable path, auto-start, no description | `…\Services\`; System **7045** |
| 17 | **Persistence — WMI Event Subscription (T1546.003)** | Fileless `__EventFilter`+`CommandLineEventConsumer`+`__FilterToConsumerBinding` | root\subscription; Sysmon EID **19/20/21** |
| 18 | **DLL search-order hijack (T1574.001)** | Unsigned DLL loaded from app dir before System32 | Sysmon EID 7 (signed/signature fields) |
| 19 | **Malicious browser extension (T1176)** | Extension with broad host + cookie/webRequest perms | Browser Extensions folder / enterprise policy |
| 20 | **C2 — App Layer Protocol (T1071)** + beaconing | Fixed-interval callbacks (with jitter) to same host; rare TLS cert/JA3; young/rare domain | Sysmon EID 3 (net, off by default); firewall/ASR logs |
| 21 | **C2/Exfil over DNS (T1071.004) / Protocol Tunneling (T1572)** | High-entropy/long subdomains to one zone; TXT-query bursts; NXDOMAIN bursts; DoH to odd resolver | Sysmon EID **22** (process-attributed DNS, Win8.1+); DNS-Client ETW |
| 22 | **Exfil over Web Service (T1567)** | Outbound spike to messaging/cloud (Telegram/Discord/Pastebin) from non-browser proc; `.zip`/`.7z` created right before upload | EID 3 + EID 11 |
| 23 | **LOLBins / LOTL** (certutil/mshta/rundll32/regsvr32/powershell) | Signed MS binary making network connection or weird args (`certutil -urlcache`, `mshta http…`, `powershell -enc -nop -w hidden`) | Sysmon EID 1 cmdline; Security 4688; PowerShell 4104 |
| 24 | **USB hardware keylogger** | Inline dongle — **invisible to software** (no driver/process); at best an extra HID/USB-storage enumeration | Physical inspection; `setupapi.dev.log`, `USBSTOR`/`HID` registry |
| 25 | **BadUSB / malicious HID (Rubber Ducky)** | New keyboard device enumerated, then a process launch within ms at superhuman typing speed | DriverFrameworks-UserMode logs; keystroke-timing heuristic |
| 26 | **Evil Maid / bootkit** | TPM PCR / measured-boot mismatch; unexpected BCD/firmware change; BitLocker recovery prompt | TPM attestation; measured boot; BCD |
| 27 | **Rootkit / DKOM hidden process** | Process visible to kernel enum but absent from user-mode API lists | Cross-view diff; CodeIntegrity log EID 3033 (blocked load) |
| 28 | **Anti-forensic raw disk read** | User proc reading `\\.\` raw volume to bypass ACLs | Sysmon **EID 9** (RawAccessRead) |

---

## 2. Detection signal catalog (Windows — concrete API/registry/log per signal)

### 2.1 Process anomalies
- **Parent→child lineage:** Sysmon **EID 1** (`ParentImage`, `ParentCommandLine`, full `CommandLine`, image SHA/IMPHASH) or ETW Kernel-Process; live via WMI `Win32_Process.ParentProcessId` / `Get-CimInstance Win32_Process`. **Anomaly:** `winword.exe→cmd/powershell`, `services.exe` spawning non-system binary. Elastic ships a prebuilt "Unusual Parent-Child Relationship" rule.
- **PPID spoofing:** Sysmon EID 1 vs EID 10 discrepancy (process opened parent with `PROCESS_CREATE_PROCESS` 0x0080 then claims a different parent).
- **Unsigned binary:** Sysmon EID 1 doesn't sign — use Autoruns/Sigcheck or WDAC/AppLocker (Event 8003/8004). DLLs: Sysmon **EID 7** carries `Signed`/`Signature`/`SignatureStatus`.
- **Execution from temp/appdata:** EID 1 `Image` path under `%TEMP%`, `%APPDATA%\Roaming`, `%LOCALAPPDATA%`, `Downloads`, `\Users\Public`, `C:\ProgramData`.
- **Injection / hidden code:** Sysmon **EID 8** (CreateRemoteThread: `StartAddress/StartModule/StartFunction`), **EID 10** (ProcessAccess — lsass handle opens), **EID 25** (ProcessTampering — hollowing). VirtualAllocEx(RWX)→WriteProcessMemory→CreateRemoteThread chain; empty `StartModule`.
- **Hidden windows:** EID 1 cmdline `-WindowStyle Hidden`/`-w hidden`.

### 2.2 Network
- **Active conn + owning PID:** **`GetExtendedTcpTable`** (iphlpapi.h) with `TCP_TABLE_OWNER_PID_ALL/_CONNECTIONS/_LISTENER`, returns `MIB_TCPTABLE_OWNER_PID` rows each with `dwOwningPid`. UDP: `GetExtendedUdpTable`. CLI: `netstat -ano -b`, `Get-NetTCPConnection -OwningProcess`. Python: `psutil.net_connections()`.
- **Beaconing:** Sysmon **EID 3** (NetworkConnect — **off by default**) per-connection src process/IP/ports/hostnames; aggregate over time for fixed-interval periodicity + uniform small request sizes.
- **DNS:** Sysmon **EID 22** (DnsQuery — process-attributed, Win8.1+) gives querying proc + queried name. Anomaly: newly-registered/DGA domain, DNS from non-browser proc.
- **Listening ports:** `GetExtendedTcpTable` LISTENER; watch RAT ports 3389 (RDP), 5900/5500 (VNC), 5938 (TeamViewer), 6568 (AnyDesk).

### 2.3 Persistence enumeration (autoruns surface)
One-shot tool = Sysinternals **autorunsc** (covers all below). Maps to T1547/T1053/T1543/T1546.003.

| Surface | Path / source | Event |
|---|---|---|
| Run/RunOnce keys | `HKCU/HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,`RunOnce` | Sysmon EID 13 |
| Startup folder | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Sysmon EID 11 |
| Scheduled tasks | `\System32\Tasks\`; `TaskCache\Tree`; `Get-ScheduledTask` | Security 4698 |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services`; `Get-Service` | System 7045 |
| WMI subscription | root\subscription | Sysmon 19/20/21 |
| LSA auth packages (T1547.002) / port monitors (T1547.010) | `…\Control\Lsa\` "Authentication Packages"; `…\Control\Print\Monitors` | — |

### 2.4 Webcam / microphone usage — the highest-signal live check
- **CapabilityAccessManager ConsentStore:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam` and `\microphone` (HKLM variant per-machine). Each app subkey (Win32 apps under **`NonPackaged`**, path-encoded) holds **`LastUsedTimeStart`** and **`LastUsedTimeStop`** (FILETIME).
- **`LastUsedTimeStop = 0` → device is in use RIGHT NOW.** Subkey name = the process. Unfamiliar/NonPackaged proc with Stop=0 = active capture. Maps T1125/T1123.
- LED is a hardware signal but **malware can sometimes suppress it** (UNVERIFIED this pass) — treat registry as authoritative.

### 2.5 Input capture (keylogging) — T1056.001
Velociraptor `Windows.Detection.Keylogger` reads Win32k ETW (`{8c416c79-d49b-4f01-a467-e56d3aa8234c}`):
- **EID 1002** `FilterType=0xD` (13 = WH_KEYBOARD_LL); also `WH_KEYBOARD=2`.
- **EID 1001** `Flags=256` (RIDEV_INPUTSINK — background capture without focus; rare in legit apps).
- **EID 1003** `MsSinceLastKeyEvent>100` AND `BackgroundCallCount>400` (tight polling loop).
- Exclude Explorer.exe; enrich with process metadata. **Kernel filter-driver keyloggers won't show here** — catch via §2.6 driver signals.

### 2.6 Driver / rootkit signals
- **Driver load:** Sysmon **EID 6** (hash + signature); ETW Kernel-PnP; `Services\*` Type=1. Anomaly: unsigned/revoked or signed-but-vulnerable BYOVD driver from odd path.
- **Raw disk access:** Sysmon **EID 9** (RawAccessRead) — `\\.\` device reads.
- **Hidden process cross-view:** compare GetExtendedTcpTable/Toolhelp32 vs ETW/kernel callbacks (DKOM detection).
- **CodeIntegrity:** `Microsoft-Windows-CodeIntegrity/Operational` EID **3033** (blocked load); Vulnerable Driver Blocklist / HVCI events.

### 2.7 Telemetry frameworks (data plane)
- **Sysmon** (`Microsoft-Windows-Sysmon/Operational`). Key IDs: **1** ProcessCreate, **3** NetworkConnect, **6** DriverLoad, **7** ImageLoad, **8** CreateRemoteThread, **9** RawAccessRead, **10** ProcessAccess, **11** FileCreate, **12/13/14** Registry, **17/18** named pipes, **19/20/21** WMI, **22** DnsQuery, **23/26** FileDelete, **25** ProcessTampering. EID 3/7/10 high-volume → filter. EID 22 needs Win8.1+.
- **ETW providers** (no Sysmon needed): Kernel-Process, Kernel-Network/TcpIp, DNS-Client, **Win32k** (input hooks §2.5), CodeIntegrity, WMI-Activity. Drive via `logman`/`wevtutil`/krabsetw.
- **Defender logs:** `Microsoft-Windows-Windows Defender/Operational` EID **1116/1117** (detection/action), **5001** (RTP disabled), **5007** (config changed = tampering signal); ASR audit events.

### 2.8 Remote-access indicators
- **Active RDP session:** `qwinsta`/`query session`; `Get-RDUserSession`.
- **RDP logon:** `TerminalServices-RemoteConnectionManager/Operational` **EID 1149** (shows source); `LocalSessionManager/Operational` **21/22/24/25/23**; Security **4624 Type 10** / **4778/4779**.
- **TeamViewer:** service `TeamViewer`; `Connections_incoming.txt`, `TeamViewer*_Logfile.log`; ports 5938→443/80.
- **AnyDesk:** service `AnyDesk`; `%PROGRAMDATA%\AnyDesk\` + `%APPDATA%\AnyDesk\` (`ad.trace`, `connection_trace.txt`); ports 6568/80/443.

**Fastest triage order:** (1) `qwinsta` + listening/established connections by PID; (2) ConsentStore webcam/mic `Stop=0` (live spying now); (3) autorunsc persistence → flag unsigned+temp; (4) Sysmon 1/8/10/22; (5) Win32k ETW 1001/1002 + Sysmon EID 6.

---

## 3. Build-on-this — OSS tools/libraries to leverage

**License lens (Nino wants MIT-friendly shippable code):**
- **Bundle/link freely (permissive):** psutil, pywin32, WMI (BSD/permissive); YARA/YARA-X/yara-python (BSD-3); osquery (**pick Apache-2.0** of its Apache-2.0/GPLv2 dual); Zeek (BSD-3); Sigma rules + signature-base (DRL 1.1); pySigma/sigma-cli (BSD).
- **Use as separate process / standalone only (copyleft):** ClamAV/libclamav (GPLv2), tshark/Wireshark (GPLv2+), Suricata (GPLv2), Wazuh/OSSEC (GPLv2), rkhunter/chkrootkit (GPL), Loki (GPLv3), **scapy (GPLv2 — the one outlier; keep out of MIT core)**, **Velociraptor (AGPLv3 — strictest, do NOT embed)**.
- **Detect-and-invoke a user-installed copy, NEVER redistribute (proprietary-free):** all Sysinternals (autorunsc, Sigcheck, Sysmon, Process Explorer, Handle, TCPView), Windows Defender MpCmdRun, THOR Lite, GMER.
- **External data, verify terms:** abuse.ch URLhaus/ThreatFox — fair-use, **Auth-Key from auth.abuse.ch now required** (Spamhaus, 2026), not CC0.

| Tool | What | License | How to call |
|---|---|---|---|
| **psutil** | Cross-platform processes/connections/open files | BSD-3 ✅import | `psutil.process_iter([...])`, `net_connections()` |
| **pywin32** | Win32 API + Event Log + WMI + services | PSF/BSD-style ✅ (check bundled components if redistributing) | `import win32evtlog, win32service` |
| **WMI** | Thin wrapper for WMI (autostart, drivers, persistence) | BSD/MIT-style ✅ | `import wmi; c.Win32_Process()` |
| **osquery** | SQL over OS state (processes, ports, autoexec, kernel_modules, registry, hashes) + snapshot/differential diffing + FIM | Apache-2.0 ✅ (dual) | `osqueryi --json "SELECT * FROM autoexec;"` — shell out, parse JSON |
| **YARA-X** (succ. to YARA, maint-mode) | File/memory pattern match | BSD-3 ✅ | `yara` CLI; Python/Go/C bindings; legacy `yara.compile().match()` |
| **Sigma** + **sigma-cli/pySigma** | Log-detection rules ("YARA for logs") | rules DRL 1.1 ✅ / tooling BSD ✅ | `sigma convert -t <backend> -p sysmon <rules>` |
| **signature-base** (Neo23x0) | Curated YARA+IOC DB | DRL 1.1 ✅ (was GPL pre-2021) | bundle as default ruleset |
| **Sysinternals autorunsc** | ALL autostart vectors + hashes + sig-verify | proprietary-free, NO redistribute | `autorunsc -accepteula -a * -c -h -s -nobanner` → CSV (add `-vt` for VirusTotal). Suppress EULA via `-accepteula` or `HKCU\Software\Sysinternals\<tool>\EulaAccepted=1` |
| **Sysinternals Sigcheck** | Signature + VT hash check | proprietary-free | `sigcheck -accepteula -c -h -vt <path>` |
| **Sysmon** | Kernel telemetry → Event Log | proprietary-free, install-don't-ship | `sysmon -accepteula -i config.xml` (pair SwiftOnSecurity or Olaf Hartong config) |
| **Windows Defender MpCmdRun** | Built-in AV scan, zero-install everywhere | proprietary-free | `MpCmdRun.exe -Scan -ScanType 3 -File <path>`; PS `Start-MpScan`/`Get-MpThreat` |
| **ClamAV** | OSS AV engine | GPLv2 ⚠️ subprocess | `clamscan -r <path>`; `freshclam`; or `clamd` socket |
| **Loki** + signature-base | Simple IOC+YARA scanner | GPLv3 ⚠️ subprocess | `python loki.py -p <path>` |
| **Zeek** | Network session/conn/dns/http/ssl logs | BSD-3 ✅ (Linux sensor; weak Win) | scriptable; best license fit for net logic |
| **Suricata** | IDS/IPS, Snort-rule compatible, EVE JSON | GPLv2 ⚠️ standalone | consume `eve.json` |
| **tshark** | Packet capture/dissection | GPLv2+ ⚠️ subprocess | `tshark -i <iface> -f "tcp"` |
| **pefile** + Authenticode | PE parse + signer/signature | permissive ✅ | `pefile`; or PS `Get-AuthenticodeSignature` |
| **abuse.ch URLhaus/ThreatFox** | IOC feeds (URLs, hashes, C2) | fair-use, Auth-Key required ⚠️ verify terms | `POST https://urlhaus-api.abuse.ch/v1/` |

**Recommended permissive spine:** psutil + pywin32/WMI (collection) → osquery Apache-2.0 (deep OS state) → YARA-X + signature-base/Sigma (content) → orchestrate Sysmon, Defender, optionally ClamAV/Suricata as **external processes**. Keeps shippable code MIT-clean while leveraging copyleft/proprietary at arm's length.

**Skip:** GMER (unmaintained, unreliable on Win10/11 PatchGuard); rkhunter/chkrootkit (Linux-only — irrelevant to a Windows agent).

---

## 4. Cross-device strategy

### TinyCheck (Kaspersky GReAT, OSS) — the universal agentless layer
Put the suspect device behind a monitored Wi-Fi hotspot, inspect outbound traffic for known C2/spyware servers + heuristics. Works on **any Wi-Fi device** (iOS/Android/IoT/smart-TV) because detection is **off-device** → **invisible to the spyware/abuser** (critical for stalkerware victims who can't tip off an abuser). ~$50 Raspberry Pi 3+ + Wi-Fi dongle + touchscreen, Debian-like, 2 Wi-Fi ifaces (or 1 Wi-Fi + Ethernet).
- **Frontend:** ephemeral Wi-Fi AP, captures traffic to pcap.
- **Engine:** **Zeek** (session dissection) + **Suricata** (IDS) over the pcap, matched against extended IOCs + toggleable heuristics.
- **Backend:** manage custom/extended IOCs, whitelist, config.
- **Backed by** Coalition Against Stalkerware (Kaspersky, EFF, ECHAP, NNEDV) + used by NGOs/LE in EU/Australia.
- **Limits:** only catches traffic that (a) traverses Wi-Fi and (b) hits a *known* IOC or trips a heuristic. Cellular-only exfil, encrypted/CDN-fronted C2, unknown C2 evade it. Detects *communication*, not the on-device implant.
- **Note:** the architecture dumps cite different repo mirrors (virtuoushub/TinyCheck, PowerPress/TinyCheck, a Gitea mirror) — the canonical is Kaspersky's; treat mirror URLs as that.

### MVT (Mobile Verification Toolkit, Amnesty Security Lab) — deep mobile forensic layer
Detects *implant traces* by matching device artifacts against **STIX2 IOCs** (`download-iocs`). **Linux/macOS only**, custom consensual-forensics license.
- **iOS (`mvt-ios`):** acquire encrypted iTunes/Finder backup (MVT decrypts), full FS dump, or sysdiagnose; parses iOS DBs/logs/analytics. Key artifact **`shutdown.log`** (Pegasus sticky-process traces, `/private/var/db/` path). **iOS 26 regression: Apple now overwrites shutdown.log every reboot** (was append) → erases historical Pegasus/Predator evidence. iOS keeps more traces than Android → more reliable there, but 0-click 0-days leave minimal traces.
- **Android (`mvt-android` + AndroidQF):** **AndroidQF** acquires over **ADB (USB, no root)** — diagnostics, logs, non-system APKs; device must stay unlocked; then `check-androidqf` vs STIX2 IOCs. Proven vs **NoviSpy** (Amnesty, Dec 2024). Android leaves **fewer traces** — "non-detection ≠ clean."

### macOS — Objective-See (Patrick Wardle)
- **KnockKnock:** enumerates 60+ persistence locations + VirusTotal (point-in-time).
- **BlockBlock:** real-time monitor/block of new persistent items. (Also LuLu firewall, OverSight mic/cam.)

### Linux — no dedicated consumer anti-spyware
Use the **TinyCheck network pattern** (best) + generic host tooling (auditd, `ss` egress review, rkhunter/chkrootkit) + Zeek+Suricata on a router SPAN. (UNVERIFIED that any purpose-built Linux stalkerware scanner exists — none found.)

### Per-platform capability matrix

| Platform | On-device detection | Forensic acquisition | Network-side (agentless) | Primary OSS tool | Realistically detectable? |
|---|---|---|---|---|---|
| **Windows** | **Yes** (this tool: baseline-diff + behavioral) | Live host state | Yes (TinyCheck) | spyscan (§6) + Sysinternals/Defender/osquery | Good for persistence/RMM/known IOC; usermode misses kernel-hidden |
| **iOS (Pegasus/Predator)** | Very limited (no AV access) | Backup / full FS / sysdiagnose → STIX2 | **Yes** (TinyCheck) | **MVT** (`mvt-ios`) | Partial — iOS 26 wipes shutdown.log; 0-click minimal. Lockdown Mode = prevention only |
| **Android (stalkerware+spyware)** | Unreliable (apps hide) | **AndroidQF** over ADB → STIX2 | **Yes** (TinyCheck) | **MVT** (`mvt-android`) | Partial — fewer traces; public-IOC only |
| **macOS** | **Yes** (persistence + real-time) | Persistence enum | Possible | **KnockKnock + BlockBlock** | Good for persistence malware; in-memory/0-day hard |
| **Linux** | No dedicated tool | Generic (auditd/rkhunter) | **Yes** | TinyCheck / Zeek+Suricata | Network-side good; host-side ad hoc |
| **IoT / smart-TV / any Wi-Fi** | None | None | **Yes — only viable method** | **TinyCheck** | Only via network IOC/heuristic |

**Universal blind spot (all platforms):** everything relies on **known IOCs/heuristics**. Unknown C2, cellular-only exfil, and Apple's own log-rotation defeat them. **"No detection" never means "clean."**

---

## 5. False-positive & legal/ethical guardrails

### 5.1 Hardening first (prevention beats detection — do these before building detection)
- **Defender ASR rules** (work on Home; `Set-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -..._Actions <1 Block|2 Audit|6 Warn>`). High-value for spyware: Block LSASS credential stealing `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (or use LSA Protection + Credential Guard instead); Block WMI-subscription persistence `e6db77e5-3df2-4cf1-b95a-636979351e5b`; Block PSExec/WMI process creation `d1e49aac-8f56-4280-b9ba-993a6d77406c`; Block untrusted USB processes `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4`; Block exploited vulnerable signed drivers (BYOVD) `56a863a9-875e-4185-98a7-b882c64b5ce5`; Block obfuscated scripts `5beb7efe-fd9a-4556-801d-275e5ffc04cc`. **Deploy Audit-first, then Block.** The prevalence/age rule `01443614-...` is the FP-heavy one.
- **Controlled Folder Access**, webcam/mic privacy toggles (**caveat: Win32 desktop apps can access camera/mic even with per-app toggles off — only the master "desktop apps" toggle governs them; hardware shutter is the only ironclad control**), disable unused RDP/Remote Assistance/Remote Registry/WinRM (T1219 guidance), standard non-admin account + UAC max + 2FA + BitLocker, UEFI password + Secure Boot + TPM.

### 5.2 The false-positive problem (where DIY detectors die)
Legit software that looks exactly like spyware — **distinguish by behavior chain + authorization context, not tool identity**:
- **Remote support YOU installed** (TeamViewer/AnyDesk/Chrome Remote Desktop/RustDesk) — behaviorally identical to a RAT.
- **Sync clients** (OneDrive/Dropbox/Google Drive) — read whole file tree, beacon constantly.
- **RGB/vendor utils** (iCUE/Armoury Crate/Razer Synapse/Afterburner) — kernel drivers, hook input, SYSTEM, autostart (UNVERIFIED per-vendor specifics).
- **Kernel anti-cheat** (Vanguard/EAC/BattlEye) — research measures them **meeting/exceeding rootkit thresholds**; Vanguard false-blocked legit OC/fan drivers at launch.
- **Parental controls / MDM / corporate agents** — designed to monitor; only consent/ownership differs.

**FP-suppression mechanisms to copy:**
1. **Baseline/diff over time** — *single biggest FP-killer.* Snapshot clean autostart/process/net/driver/perm state; alert only on *deltas*. A new persistence entry that appeared *today* matters; the 200 that were always there don't.
2. **Allowlisting** — narrow (per-hash or signed-publisher), never whole directories.
3. **Reputation + prevalence + first-seen** — let unknown files' trust accrue; hash-lookup VT (70+ engines).
4. **Code-signature verification** — verify Authenticode + publisher, not just "is it signed" (malware can be signed); `autorunsc -s` + hide Microsoft-signed.

### 5.3 Detection philosophy tradeoffs

| Approach | Catches | FP rate | Build cost | Notes |
|---|---|---|---|---|
| **Signature** (IOC/hash/YARA/VT) | known threats, fast+accurate | low | low | blind to 0-day/custom RAT |
| **Baseline-then-diff** | *new* persistence + config drift | low–med (if baseline clean) | low | **best ROI for one owned box**; misses things present at baseline; risk of baseline poisoning if already infected |
| **Behavioral/anomaly** | novel + fileless + LOTL | high, alert fatigue | high | mimics-normal & slow-ramp evade |

**Verdict:** lead with **baseline-diff + reputation/signature enrichment**; add a *few* high-signal behavioral checks (LSASS handle access, unsigned driver load, new outbound listener, camera/mic API use by unexpected proc). Don't build a from-scratch ML anomaly engine — alert-fatigue trap (~63% of reviewed alerts are FP/benign).

### 5.4 Legal / ethical line
- **A defensive detector on YOUR OWN device is legal** — you're authorized, you control the data.
- **The offensive line is stalkerware = federal crime:** **CFAA 18 U.S.C. §1030** + **federal Wiretap Act** + **all-50-states wiretap/surveillance laws**. "Shared family plan," gifted device, spouse's phone do **not** grant authorization. A detector and spyware share ~90% of code (keylog/screen/mic); **intent + ownership + consent are the legal divide, not the tech.**
- **Practical rule:** scope to "scan the machine it runs on, with the operator's consent." **Never add remote-deploy, covert-install, or capture-another-person features** — that's the moment you build the thing you set out to detect.

### 5.5 Operational — don't let the detector be the most invasive thing on the box
- **Local-only by default.** No cloud upload of process lists/paths/screenshots/keystrokes. VT enrichment = **hashes only, opt-in** (even a hash+filename can leak document names).
- **Least privilege.** Watching APIs/handles is enough to *detect* keylog/screen/mic — you don't need to keylog/capture to detect it. **If you ship a kernel driver for telemetry, you've added the exact BYOVD surface §5.1 warns about.**
- **Encrypt baselines/findings, local, retention limits. Signed binary** (so it isn't itself flagged). **Tamper-evidence over stealth** — a defensive tool announces itself; hiding is a spyware property; it should pass its own audit.

---

## 6. Recommended MVP architecture + phased roadmap (solo Windows dev, Python 3.14)

**Canonical EDR spine (every real tool is a variant):**
`[collectors] → [normalize] → [rule/IOC engine] → [correlate+score] → [alert] → [store] → [UI/report]`
**Architectural lesson (Wazuh):** keep collection dumb, detection central — agents ship normalized signals, a separate engine decides, so rules update without touching endpoints. **Velociraptor lesson:** detection logic as *data* (declarative VQL/artifacts), not compiled code — a small engine + growing detection library. **OpenEDR lesson:** real EDRs get process/registry truth from kernel callbacks; **in usermode you approximate with ETW+WMI+polling — good enough for an MVP, but be honest it's a scanner/triage tool, not a kernel EDR.**

**Build the host-side baseline-diff scanner first** — highest signal-per-effort, 100% local. Single Python package, no server, SQLite store.

```
spyscan/
  collectors/          # each returns normalized list[dict] of "facts"
    autoruns.py        # wraps autorunsc64.exe -a * -c -h -s -nobanner (CSV)
    processes.py       # psutil: pid, exe, hash, signer, parent, cmdline
    netconns.py        # Get-NetTCPConnection / psutil: remote ip:port + owning pid
    services.py        # services + scheduled tasks (schtasks /query /fo csv)
    drivers.py         # driverquery / loaded kernel modules
    consentstore.py    # ConsentStore webcam/mic LastUsedTimeStop=0 (live capture)
  core/
    normalize.py       # raw -> canonical fact schema (entity, type, attrs, hash)
    baseline.py        # save/load clean snapshot (SQLite); diff -> added/removed
    rules/
      yara_scan.py     # yara-python over ONLY flagged binaries (scope by suspicion)
      sigma_lite.py    # match normalized events vs curated Sigma subset
      ioc.py           # set-membership vs local domain/ip/hash feeds
    score.py           # weighted accumulation per entity -> confidence 0-100
  report/html.py       # self-contained HTML: new ASEPs, scored findings, ATT&CK tags
  cli.py               # spyscan baseline | scan | report
```

**Scoring (start dumb — it works):** score the *entity* (process/autostart/remote host), not isolated events. Each signal adds weight: unsigned +2, new ASEP since baseline +3, beacon to rare domain +3, IOC hash hit +5, runs from `%TEMP%`/AppData +2, no trusted-tree parent +2. Bucket: **≥8 ALERT, 4–7 REVIEW, <4 info.** Allowlist signed-Microsoft + known-good hashes. Persist scores so re-runs show deltas. (Correlation/time-window aggregation collapses related events into one investigation thread → fights alert fatigue.)

**Three complementary rule engines** (different evidence planes): **YARA-X** = files & memory; **Sigma** = events & logs; **IOC matching** = domains/IPs/hashes. Tag every detector with a MITRE ATT&CK technique ID for explainability + coverage map.

**Phased roadmap:**
- **Phase 0 (½ day):** vendor `autorunsc64.exe`; CSV→SQLite baseline; `baseline`/`scan`/diff for ASEPs only. Ship the new-autostarts report. (Smallest thing that detects real persistence — ~70% of spyware persistence coverage.)
- **Phase 1 (MVP, 1–2 wk):** add process/netconn/services/drivers/consentstore collectors + normalize schema; signature/hash enrichment (pefile + Authenticode); weighted scoring + allowlist; HTML report with ATT&CK tags.
- **Phase 2 (rules):** wire scope-limited `yara-python`, Sigma-subset matcher, local IOC feeds (abuse.ch w/ Auth-Key + own) with auto-update.
- **Phase 3 (live + correlation):** lightweight ETW/WMI watcher (process-create, network, registry-autostart writes) → rolling event store; time-window correlation so weak signals stack into one scored incident. The "central engine" moment.
- **Phase 4 (cross-platform + network):** factor engine into portable core; add Linux/mac osquery-backed collector OR stand up a **TinyCheck-style Pi appliance** (Zeek+Suricata over pcap) for phones/IoT you can't agent. Optional local OpenSearch + dashboard only once volume justifies an indexer.
- **Phase 5 (intel + response):** ATT&CK coverage map, IOC feed automation, **guarded** active-response (quarantine file / disable autostart) — Wazuh Active-Response model but **require human confirm** given solo-dev blast radius.

**Two warnings:** (1) usermode Python can't match kernel-callback EDRs for tamper-resistance or real-time process truth — advanced spyware can hide from usermode enumeration; ship it as scanner/triage. (2) Don't build indexer/dashboard early — SQLite + HTML report carries you a long way; the diff-and-score core is the value.

---

## 7. Open questions / UNVERIFIED

- **Webcam-LED suppression by malware** — well-established in literature, not re-confirmed against a primary source this pass. Treat ConsentStore registry as authoritative, LED as advisory.
- **DKOM hidden-process behavior** — established but not primary-source re-confirmed this pass.
- **"~28% Run-key persistence" (IBM X-Force)** — from a Picus/secondary summary, NOT the primary X-Force report.
- **autorunsc flag syntax** (`-a * -c -h -s`) and **ATT&CK IDs T1547/T1071** in the architecture dump — cited from prior tool/framework knowledge, not fetched that session. (Other dumps DID verify the same ATT&CK IDs against attack.mitre.org — cross-checked consistent.)
- **Per-vendor RGB-utility FP specifics** (iCUE/Synapse/Armoury Crate) — community-reported, no primary vendor advisory retrieved. Vanguard overclock-driver false-block + kernel-anti-cheat-as-rootkit measurements are from the cited ACM paper / search results.
- **Exact CFAA/Wiretap penalty figures** — not individually verified beyond cited summaries.
- **No purpose-built Linux consumer stalkerware scanner found** — UNVERIFIED that none exists; none surfaced in research.
- **abuse.ch terms** — Auth-Key now required; **verify fair-use/commercial terms before any redistribution** of feed data.
- **pywin32 license** — permissive per maintainer but some bundled components vary — **check before redistributing**.
- **Section disagreement (minor):** TinyCheck repo URL differs across dumps (virtuoushub/PowerPress/Gitea mirrors) — all are mirrors of Kaspersky's canonical TinyCheck; use the Kaspersky-blog reference as source of truth.

---

## 8. Consolidated sources (deduped real URLs)

**MITRE ATT&CK**
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1123/
- https://attack.mitre.org/techniques/T1125/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1115/
- https://attack.mitre.org/techniques/T1546/
- https://attack.mitre.org/versions/v15/techniques/T1219/
- https://attack.mitre.org/techniques/T1219/
- https://attack.mitre.org/techniques/T1572/
- https://attack.mitre.org/techniques/T1547/002/
- https://attack.mitre.org/detectionstrategies/DET0221/
- https://attack.mitre.org/software/S0348/

**Detection rules / hunting**
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.yaml
- https://www.manageengine.com/log-management/mitre-attack/persistence.html
- https://www.manageengine.com/log-management/mitre-attack/persistence/boot-autostart-execution-t1547.html
- https://www.manageengine.com/log-management/mitre-attack/command-and-control.html
- https://www.elastic.co/guide/en/security/8.19/persistence-via-wmi-event-subscription.html
- https://www.elastic.co/guide/en/security/current/unusual-parent-child-relationship.html
- https://detect.fyi/hunting-wmi-event-subscription-persistence-f087900029f4
- https://detection.fyi/elastic/detection-rules/windows/defense_evasion_parent_process_pid_spoofing/
- https://www.picussecurity.com/resource/blog/t1547-boot-or-logon-autostart-execution
- https://www.startupdefense.io/mitre-attack-techniques/t1056-001-keylogging
- https://www.startupdefense.io/mitre-attack-techniques/t1055-process-injection

**Malware analysis (hVNC / stealers / RATs)**
- https://www.elastic.co/security-labs/elastic-security-labs-discovers-lobshot-malware
- https://www.bleepingcomputer.com/news/security/new-lobshot-malware-gives-hackers-hidden-vnc-access-to-windows-devices/
- https://www.cybereason.com/blog/behind-closed-doors-the-rise-of-hidden-malicious-remote-access
- https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/detect-suspicious-processes-running-on-hidden-desktops/4072322
- https://spycloud.com/blog/infostealers-bypass-new-chrome-security-feature/
- https://redcanary.com/blog/threat-intelligence/google-chrome-app-bound-encryption/
- https://www.kaspersky.com/blog/chrome-application-bound-encryption-bypass-voidstealer/55735/
- https://www.cyberark.com/resources/threat-research-blog/c4-bomb-blowing-up-chromes-appbound-cookie-encryption
- https://www.bleepingcomputer.com/news/security/infostealer-malware-bypasses-chromes-new-cookie-theft-defenses/
- https://deepstrike.io/blog/infostealer-malware-credential-theft-2025
- https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer
- https://deepstrike.io/blog/what-is-living-off-the-land-binaries-lolbins
- https://www.stationx.net/lolbins-living-off-the-land-binaries/

**Stalkerware / Coalition**
- https://github.com/AssoEchap/stalkerware-indicators
- https://securelist.com/state-of-stalkerware-2023/112135/
- https://stopstalkerware.org/2022/06/28/visit-tinychecks-brand-new-page-a-free-open-source-tool-for-detecting-stalkerware-on-your-mobile-device/
- https://www.malwarebytes.com/blog/news/2021/03/coalition-against-stalkerware-partners-tool-finds-stalkerware-in-new-way

**Hardware / BadUSB / evil maid**
- https://arxiv.org/pdf/2302.04541
- https://github.com/withdk/badusb2-mitm-poc

**Windows APIs / signals / forensics**
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
- https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable_owner_pid
- https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.capabilityaccessmanager/
- https://www.cyberengage.org/post/registry-system-configiuration-tracking-microphone-and-camera-usage-in-windows-program-execution
- https://davidarno.org/using-the-registry-to-monitor-webcam-and-microphone-use/
- https://docs.velociraptor.app/exchange/artifacts/pages/windows.detection.keylogger/
- https://woshub.com/rdp-connection-logs-forensics-windows/
- https://ss64.com/nt/query-session.html
- https://www.mdpi.com/2079-9292/13/8/1429
- https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects
- https://www.blackhillsinfosec.com/a-sysmon-event-id-breakdown/

**OSS tools / licenses**
- https://learn.microsoft.com/en-us/sysinternals/license-terms
- https://learn.microsoft.com/en-us/sysinternals/license-faq
- https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- https://github.com/osquery/osquery
- https://github.com/osquery/osquery/blob/master/LICENSE
- https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/
- https://osquery.readthedocs.io/en/stable/deployment/configuration/
- https://docs.velociraptor.app/blog/2020/2020-12-13-velociraptor-and-osquery-2a4306dd23c/
- https://github.com/Velocidex/velociraptor/blob/master/LICENSE
- https://docs.velociraptor.app/docs/overview/
- https://github.com/wazuh/wazuh/blob/main/LICENSE
- https://documentation.wazuh.com/current/getting-started/architecture.html
- https://documentation.wazuh.com/current/getting-started/components/wazuh-server.html
- https://en.wikipedia.org/wiki/OSSEC
- https://github.com/ComodoSecurity/openedr
- https://techtalk.comodo.com/2020/09/19/open-edr-components/
- https://github.com/VirusTotal/yara
- https://github.com/SigmaHQ/sigma
- https://github.com/SigmaHQ/sigma-cli
- https://github.com/Neo23x0/Loki
- https://github.com/Neo23x0/signature-base/
- https://www.nextron-systems.com/valhalla/
- https://sourceforge.net/p/rkhunter/wiki/license/
- https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
- https://learn.microsoft.com/en-us/defender-endpoint/run-scan-microsoft-defender-antivirus
- https://docs.clamav.net/
- https://github.com/Cisco-Talos/clamav
- https://zeek.org/faq/
- https://github.com/zeek/zeek
- https://www.stamus-networks.com/suricata-vs-zeek
- https://www.wireshark.org/faq.html
- https://wiki.wireshark.org/License
- https://urlhaus.abuse.ch/api/
- https://threatfox.abuse.ch/api/
- https://www.spamhaus.com/data-access/abusech-api/
- https://pypi.org/project/psutil/
- https://github.com/giampaolo/psutil/blob/master/LICENSE
- https://github.com/mhammond/pywin32/issues/1646
- https://pypi.org/project/WMI/
- https://github.com/secdev/scapy/blob/master/LICENSE
- https://www.sans.org/blog/offline-autoruns-revisited-auditing-malware-persistence

**Detection theory / scoring / architecture**
- https://mlab.sh/compare/yara-vs-sigma
- https://harfanglab.io/blog/product/perks-sigma-yara-edr/
- https://encyb.com/blogs/yara-sigma-threat-detection
- https://panther.com/blog/your-guide-to-the-sigma-rules-open-standard-for-threat-detection
- https://daylight.ai/blog/alert-fatigue-in-cybersecurity
- https://www.rapid7.com/fundamentals/alert-fatigue-cybersecurity/
- https://www.ncbi.nlm.nih.gov/pmc/articles/PMC3752621/
- https://www.noze.it/en/insights/velociraptor-dfir/
- https://www.pentestpartners.com/security-blog/using-velociraptor-for-large-scale-endpoint-visibility-and-rapid-threat-hunting/
- https://www.sentinelone.com/cybersecurity-101/cybersecurity/signature-based-vs-behavioral-ai-detection/
- https://www.cisecurity.org/insights/spotlight/cybersecurity-spotlight-signature-based-vs-anomaly-based-detection
- https://dl.acm.org/doi/fullHtml/10.1145/3664476.3670433

**Mobile / cross-device**
- https://github.com/mvt-project/mvt
- https://docs.mvt.re/en/latest/introduction/
- https://securitylab.amnesty.org/latest/2024/12/tech-guide-detecting-novispy-spyware-with-androidqf-and-the-mobile-verification-toolkit-mvt/
- https://github.com/virtuoushub/TinyCheck
- https://github.com/PowerPress/TinyCheck
- https://rlp.schule/gitea/c_meyer/KasperskyLab-TinyCheck/src/commit/e3e14ddaf9bedb1c01d9c1fb22d3c51f1877b716/README.md
- https://www.kaspersky.com/blog/tinycheck-detects-spyware-stalkerware/38030/
- https://iverify.io/blog/key-iocs-for-pegasus-and-predator-spyware-cleaned-with-ios-26-update
- https://cybernews.com/news/apple-iphone-forensic-trace-pegasus-iverify/
- https://www.bitdefender.com/en-us/blog/hotforsecurity/what-is-lockdown-mode-iphone-mac-spyware-when-use-it
- https://www.techtimes.com/articles/300790/20240119/iphone-spyware-threat-kaspersky-recommends-method-detect-pegasus-spyware.htm
- https://objective-see.org/tools.html
- https://objective-see.org/products/knockknock.html
- https://objective-see.org/products/blockblock.html

**Hardening / privacy / legal**
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview
- https://learn.microsoft.com/en-us/defender-endpoint/enable-attack-surface-reduction
- https://support.microsoft.com/en-us/windows/windows-camera-microphone-and-privacy-a83257bc-e990-d54a-d212-b5e41beba857
- https://support.microsoft.com/en-us/windows/manage-app-permissions-for-a-camera-in-windows-87ebc757-1f87-7bbf-84b5-0686afb6ca6b
- https://legalclarity.org/is-spyware-legal-federal-and-state-laws-explained/
- https://www.womenslaw.org/about-abuse/abuse-using-technology/ways-survivors-use-and-abusers-misuse-technology/computer-3
- https://www.acronis.com/en/blog/posts/how-msps-can-reduce-edr-false-positives-and-reclaim-profit-margins/
