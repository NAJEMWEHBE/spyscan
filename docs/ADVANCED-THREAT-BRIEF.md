# Advanced-Threat Detection Brief (nation-state / mercenary spyware)

**Scope:** Defensive detection reference for a personal "spy-detector." Every family/TTP is described only at the level needed to RECOGNIZE its forensic residue on a device or network. No deployment/offensive guidance. Items not confirmed against a primary source are flagged **UNVERIFIED**.

**Two anchoring truths from the primary sources:**
- Mercenary implants try to scrub their traces and **fail imperfectly** — Amnesty's **CASCADEFAIL**: Pegasus deletes a process name from `ZPROCESS` in `DataUsage.sqlite` but leaves the orphaned `ZLIVEUSAGE` row. **Inconsistent deletion is itself a high-confidence signal.**
- A **compromised device cannot be trusted to report on itself** — pair on-device forensics (MVT) with an **off-device observer** (gateway/radio sensor) and **tripwires** (canary tokens) that fire on the one thing an unknown implant must eventually do.

---

## 1. The mercenary / APT threat landscape

| Actor / family (vendor) | Delivery vector | Detectable artifact / IOC (defensive signal) | Source |
|---|---|---|---|
| **Pegasus** (NSO Group) | Zero-click iMessage (`com.apple.madrid`; FORCEDENTRY/BLASTPASS era); historic 1-click SMS; Safari network injection | Disguised processes `bh` (BridgeHead), `roleaccountd`, `roleaboutd`, `stagingd`, `msgacntd`, `mptbd`, `ckkeyrollfd`, `fmld`, `pcsd`, `gatekeeperd`, `otpgrefd`; `com.apple.coretelephony` doing HTTP. Paths `/private/var/db/com.apple.xpc.roleaccountd.staging/`, payloads in `com.apple.coretelephony/Cache.db` + `com.apple.Music/Cache.db`. `CrashReporter.plist` disabled post-exploit. iMessage lookups in `idstatuscache.plist`. Domains `free247downloads[.]com`, `urlpush[.]net` (wildcards `*.get1tn0w.free247downloads[.]com`, `*.info8fvhgl3.urlpush.net`), `opposedarrangement[.]net`, `documentpro[.]org`; high non-standard ports (`:30495`,`:31052`). Orphaned `ZLIVEUSAGE` rows. | Amnesty Forensic Methodology Report (2021); MVT |
| **Predator** (Intellexa/Cytrox) | 1-click links (WhatsApp/SMS spoofing news + shorteners); ISP/rogue-cell injection; loader **ALIEN** → implant **PREDATOR** | ALIEN+PREDATOR pair; spoofs `usereventsagent`. Validation servers fingerprint IP/device, redirect non-targets to legit sites. 5-layer C2, Tier-1 brand-spoof domains. Google TAG 2023 Egypt: `http` → `c.betly[.]me` → `sec-flare[.]com` (CVE-2023-41991/41992/41993). Persistence via Apple Shortcuts + `/private/var/keybagd/`. Later infra → Czech **FoxItech s.r.o.** | Citizen Lab "Pegasus vs. Predator"; Amnesty Predator Files (2023); Google TAG; Recorded Future |
| **Candiru / DevilsTongue** (SOURGUM) | Single-use WhatsApp URL → browser 0-day → Windows kernel LPE | **COM-hijack** at `HKLM\...\CLSID\{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}\InprocServer32` and `{7C857801-7381-11CF-884D-00AA004B2E24}\InProcServer32`. Hijack DLLs in `C:\Windows\System32\IME\[LANG]\` (names start "im"); config `.dat` in `config\`; `physmem.sys` (MD5 `a0e2223868b6133c5712ba5ed20c3e8a`). CVE-2021-31979, CVE-2021-33771. C2 `noc-service-streamer[.]com`, `fbcdnads[.]live`, `hilocake[.]info`, `grayhornet[.]com`, `johnshopkin[.]net`. Sigma/YARA published. | Microsoft MSTIC (2021-07-15); Citizen Lab; SOC Prime |
| **Graphite** (Paragon) | Zero-click iMessage (CVE-2025-43200 via iCloud media link); zero-click WhatsApp 0-day | Android log marker **BIGPRETZEL**; iOS **SMALLPRETZEL** tied to anomalous **CloudKit** behavior. Detect via device-log analysis. | Citizen Lab "Graphite Caught" / "First Look at Paragon" (2025) |
| **Reign** (QuaDream) | Zero-click **ENDOFDAYS**: invisible backdated iCloud **calendar invites** (iOS 14.4–14.4.2) | Implant **KingsPawn** self-deletes → detect by *delivery* artifact: backdated/invisible calendar entries. Runs from `/private/var/db/`, `/private/var/tmp/`. | Citizen Lab "Sweet QuaDreams" (2023); Microsoft |
| **FinSpy / FinFisher** (Gamma, historical) | Trojanized installer/apps; ISP injection; UEFI bootkit | ESET `Win32/FinSpy.AA`/`.AB`; macOS/Linux/Android YARA (Amnesty 2020); UEFI bootkit injects at boot (Kaspersky GReAT); Citizen Lab found 70+ C2 via protocol fingerprint. | Amnesty (2020); Kaspersky; ESET KB6558; Citizen Lab |
| **RCS / Galileo** (Hacking Team, historical) | Phishing Office macros; exploit docs; network injection | Modular C2 (master DB + collector + anonymizer proxy chain = proxy-hop pattern). "Elite" implant maps shared-memory region named with 7-alphanumeric string (4ARMED Volatility plugin recovers PID/watermark/C2). Source leaked 2015; ESET found post-leak variants. | Citizen Lab (2014); 4ARMED; ESET (2018) |
| **Cellebrite UFED + NoviSpy** (extraction→implant) | Physical access; UFED bypasses Android lock, sideloads **NoviSpy** (Serbia) | Unexplained unlock/extraction artifacts; WhatsApp/Telegram/Viber extraction traces; Qualcomm 0-day (Oct 2024). NoviSpy IOCs + MVT-Android. Signal found code-exec bugs in UFED itself. **NoviSpy file-level IOCs = UNVERIFIED here** (in Amnesty PDF/GitHub, not retrieved). | Amnesty "A Digital Prison: Serbia" (2024); Signal (2021) |

**Targeting mechanics:** recon needs only the iMessage/WhatsApp-linked phone number or Apple ID email → zero-click chain. ATT&CK map: recon T1589/T1598(.004 vishing); access T1566.001/.002 (Ent)/T1660 (Mobile), drive-by T1456, zero-click T1664/T1658, OAuth-consent T1528, SIM-swap T1451, supply-chain T1474, evil-maid T1200/T1542; injection T1557/T1638; collection T1429/T1512/T1430/T1417/T1636.*/T1513; C2 T1437, OOB-SMS T1644. **UNVERIFIED:** exact ATT&CK T-IDs formally attributed to Cytrox/Predator (mapped by analogy — confirm vs ATT&CK Predator entry).

---

## 2. Detection by layer (mapped to the phased tool)

**(a) On-device host artifacts/IOC.**
- *iOS (via MVT):* `DataUsage.sqlite`+`netusage.sqlite` (per-process WWAN, name anomalies, orphaned `ZLIVEUSAGE`); `shutdown.log` (reboot-resident procs from staging paths — *only writes on reboot*); `Cache.db`/WebKit/`favicon.db`/IndexedDB (recovers exploit domains after history wipe); `idstatuscache.plist` (zero-click iMessage lookups); `applications` (non-store apps); `configuration_profiles` (rogue MDM); `tcc` (mic/cam/loc grants); `shortcuts` (persistence); `CrashReporter.plist` disabled. **Anomaly logic** = daemons masquerading as real ones (`bh`, `roleaccountd`, typosquat `aggregatenotd` vs real `aggregated`).
- *Windows (Candiru):* COM-hijack `InprocServer32` CLSID overrides, rogue `IME\*` DLLs, `physmem.sys`, the two CVEs — hunt via Sigma/YARA + CLSID review.
- *Android:* sideloaded/non-Play packages + APK-hash match; SMS links vs IOC domains; **accessibility-service abuse** (`dumpsys`); BIGPRETZEL + NoviSpy via MVT-Android.

**(b) Mobile forensic — MVT (Amnesty).** Consensual: acquire → match against **STIX2** feeds; builds a chronological **timeline** (look for redirect/iMessage-lookup → crash-reporter disabled → `bh` → cache-dir payload). iOS depth: *encrypted* backup (unlocks `DataUsage.sqlite`) < sysdiagnose (adds `shutdown.log`, `netusage.sqlite`) < full FS dump. Android: `check-adb`, `check-androidqf` (preferred), `download-apks`. IOC engine: `--iocs`/`MVT_STIX2`/`check-iocs` re-scan. STIX2 subset = `domain-name`, `url`, `process:name`, `email-addr`, `file:name/path`, `file:hashes.*`, `app:id`, `configuration-profile:id`, `android-property:name`. **Project caveat (surface in every report): a clean MVT result ≠ clean device.** Verdict: **invoke MVT as a subprocess; do NOT reimplement.**

**(c) Network-side (off-device).** *IP/traffic:* TinyCheck (Kaspersky) — Pi dual-Wi-Fi captive AP, pcap of servers contacted (no payload), analyzed with **Zeek + Suricata** vs curated IOC lists (malicious nameservers/FreeDNS/CIDR) → red/green. **PiRogue** = real-time successor (NFStream + Suricata + tshark + optional consensual mitmproxy), integrates MVT. *Network injection (Pegasus):* wire signature = unexpected redirect from a legit `http` site to an unfamiliar staging domain on a high port via validation hops; catch with Zeek `ssl.log` + **JA3/JA3S/JA4** fingerprints (Amnesty built a JA3S-style Pegasus fingerprint) + wildcard-subdomain/NRD IOC feed. *Beaconing (signature-free):* **RITA** scores interval+jitter+size periodicity over Zeek conn logs (works on encrypted/novel C2). *DNS C2:* abuse.ch **ThreatFox** RPZ + Suricata ruleset (~5-min), **URLhaus** ruleset, NRD/FreeDNS heuristic. *IMSI-catcher (SEPARATE radio sensor — IP gateway blind):* **Rayhunter** (EFF 2025; Orbic RC400L; QMDL control-plane; flags 2G-downgrade + "IMSI sent without auth"; local UI) = turnkey; **Crocodile Hunter** (SDR + srsLTE, LTE eNodeB); **SnoopSnitch** (rooted Qualcomm); **SeaGlass** (city-wide). All = **leads, not proof**; Rayhunter 2G signature US-tuned.

**(d) Deception + behavioral.** **Canary tokens** (free at canarytokens.org, Thinkst; self-hostable) = strongest no-signature primitive; plant tripwires firing **out-of-band** on touch. Best: **cloud API-key token** (fake AWS/Azure creds, fires on *use*, ~zero FP), **Office/PDF doc token** (open), **Windows folder token** (Explorer browse), **DNS token** (escapes egress filtering). Seed realistic decoys (`passwords.pdf`, fake `~/.aws/credentials`) across PC+phone+cloud; never open them yourself. Lineage: Yuill *Honeyfiles*, Bowen/Stolfo *Decoy Documents*. Limit: detects *interaction with bait* only. **Behavioral side-channels = triage prompts, never proof:** battery/heat/data spikes **low** (mundane confounders — vendor consensus Kaspersky/Bitdefender); idle network activity observed out-of-band **moderate** (most useful); mic/cam dot with no app reason **moderate** (zero-click often avoids sensors); slow shutdown = real basis (shutdown.log). A single soft signal = noise; a persisting *cluster* warrants a forensic pass.

---

## 3. Per-platform detectability matrix (honest about NOT-live-detectable)

| Signal class | Windows | Android | iOS (backup) | iOS (sysdiag/FS) |
|---|---|---|---|---|
| Malicious process-name anomaly | ◑ EDR/reg | ◑ dumpsys | ✅ DataUsage | ✅ + netusage (timed) |
| Implant network-usage timeframe | ◑ | ◑ | ◑ DataUsage only | ✅ netusage |
| Reboot-resident residue | ◑ Autoruns | ❌ | ❌ | ✅ shutdown.log (reboot-gated) |
| Exploit/redirect domains | ◑ | ✅ SMS/browser | ✅ Safari/WebKit | ✅ |
| Wiped-history recovery (favicon/IndexedDB) | ◑ | ◑ | ✅ | ✅ |
| Zero-click iMessage lookups | n/a | n/a | ✅ idstatuscache | ✅ |
| Rogue config/MDM profile | ◑ GPO | n/a | ✅ | ✅ |
| Non-store/sideloaded app | ◑ | ✅ pkg/APK hash | ✅ applications | ✅ |
| Accessibility-service abuse | n/a | ✅ dumpsys | n/a | n/a |
| COM-hijack / kernel-driver persistence | ✅ Sigma/YARA/CLSID | n/a | n/a | n/a |
| Tampering tells (orphan rows, disabled crash reporter) | ◑ | ◑ | ✅ | ✅ |
| STIX2 hash/domain/email match | ✅ | ✅ | ✅ | ✅ |
| **LIVE implant on a healthy patched device** | **❌** | **❌** | **❌** | **❌** |

✅ strong · ◑ partial · ❌ not available. **What is NOT detectable live:**
- **Novel/zero-day implants with no published IOC** trip nothing in MVT — detection is **retrospective and IOC-bound**. Hence Lockdown Mode (prevention), canary tokens (behavior), gateway watch (egress) are complementary.
- **In-memory/non-persistent iOS implants** (classic Pegasus) vanish on reboot; absence of persistence is itself characteristic, but rebooting can destroy the only evidence.
- **`shutdown.log` only writes on reboot**; iOS 18 inactivity-reboot overwrites it. **UNVERIFIED:** secondary press claim that iOS 26 erases it on *every* reboot (not confirmed vs Apple/Citizen Lab). **Rule: acquire backup/sysdiagnose BEFORE rebooting/updating a suspect device.**
- **Self-deleting implants** (KingsPawn, Graphite) leave only delivery-stage artifacts.
- **DoH/cellular egress** bypasses a home gateway/Pi-hole — force traffic through it (DHCP + block 53/DoH) or it's blind.
- **Radio CSS detection = leads, not proof**, locale-dependent false positives.
- **Capture window vs low-and-slow beaconing:** implants beacon 1–2×/day; a 5-min capture misses them — extend duration (biggest IP-side limit).

---

## 4. Source catalog + machine-consumable IOC feeds

**Research orgs:** Citizen Lab, Amnesty Security Lab, Google TAG + Project Zero, Microsoft MSTIC, Lookout (Android), Kaspersky GReAT, ESET WeLiveSecurity, Recorded Future Insikt.

| Feed | URL | Format | Ingest |
|---|---|---|---|
| **AmnestyTech/investigations** (per-case: `2021-07-18_nso`, `2021-12-16_cytrox`, `2020-09-25_finfisher`, `2024-12-16_serbia_novispy`, `2024-05-02_wintego_helios`) | github.com/AmnestyTech/investigations | **STIX2 + YARA** | git pull per case; point `MVT_STIX2` at cache; CC-BY |
| **MVT-indicators** | github.com/mvt-project/mvt-indicators | STIX2 / `indicators.yaml` | `download-iocs` auto-pull |
| **Stalkerware-indicators** | (via MVT) | STIX2 | Android consumer-spyware |
| **MITRE ATT&CK** (Mobile; Pegasus S0289/S0316) | github.com/mitre-attack/attack-stix-data | **STIX 2.1** | tag hits → Navigator layer |
| **abuse.ch ThreatFox** | threatfox.abuse.ch/export/ | JSON/CSV/MISP/**Suricata**/RPZ | Auth-Key; RPZ on resolver; age out >6mo |
| **abuse.ch URLhaus** | urlhaus.abuse.ch/api/ | API/**Suricata**/MISP | Suricata stage |
| **abuse.ch MalwareBazaar** | bazaar.abuse.ch/export/ | hashes | hash store |
| **MISP** | misp-project.org/feeds/ | **STIX/TAXII** | hub: normalize abuse.ch→STIX, dedupe, re-export |
| **Sigma** | github.com/SigmaHQ/sigma | Sigma | behavioral log rules |
| **YARA / awesome-yara** | github.com/InQuest/awesome-yara | YARA | file/memory matching |

**Auto-ingest:** normalize internal store on **STIX 2.1** (MVT subset = min mobile field set) → scheduled delta pullers (Amnesty git, abuse.ch w/ Auth-Key, ATT&CK STIX, MISP) → aggregate/dedupe/age-out in MISP → match (MVT atomic, Sigma logs, YARA files, RITA beaconing) → map each hit to an ATT&CK Mobile technique → ATT&CK-tagged alerts. Pin commit hashes; re-run `check-iocs` on archived output when feeds update.

---

## 5. How this folds into the spy-detector (phases 1–4)

- **Phase 1 — Host artifacts/IOC.** Windows: scan CLSID `InprocServer32` overrides + `IME\*` DLLs + `physmem.sys` (Candiru Sigma/YARA). Android: non-Play packages + APK-hash + accessibility `dumpsys`. Add the **STIX2 IOC store** (Amnesty + abuse.ch via MISP) as shared backend. Output must split *known-IOC match* (high confidence) from *heuristic* (needs human review).
- **Phase 2 — Mobile forensic (MVT) + net appliance.** Consent gate + acquisition wrapper: *encrypted* iOS backup or sysdiagnose (or AndroidQF/ADB), **hard-warn: acquire before reboot/update**. Run MVT (`decrypt-backup`→`check-backup`/`check-iocs`; `check-androidqf`/`check-adb`) with `MVT_STIX2` at synced cache. Net appliance: **PiRogue on a Pi (cleanest)** OR **Windows Mobile-Hotspot capture → WSL2 Zeek/Suricata/RITA + abuse.ch feeds** (uses the RTX-4070 box already owned). Normalize MVT JSON + `*_detected.json` into findings model; ship the "clean ≠ clean device" banner.
- **Phase 3 — Injection / IMSI-catcher.** Gateway: Zeek `ssl.log` + JA3/JA3S/JA4 Pegasus fingerprints + NRD heuristic + ThreatFox RPZ; RITA beaconing (design for **long captures**). Add **separate radio sensor** (Rayhunter/Orbic, advisory only). Cross-reference gateway "odd-port redirect" with MVT `favicon.db`/WebKit/`bh`-process timeline to upgrade lead → confirmed injection.
- **Phase 4 — Deception + behavioral + OOB + confirm.** Seed canary tokens (cloud-key + Office/folder/DNS) across PC+phone+cloud, alert out-of-band. Pi-hole/gateway DNS watch for idle beaconing + reported-vs-observed discrepancy (CASCADEFAIL logic). Behavioral triage (mic/cam dot, idle data, slow shutdown) = *investigate* prompts only. Reserve shutdown.log/iShutdown + iVerify (~$1; found ~2.5 Pegasus per 1,000 scanned) + Apple/Google **Threat Notifications** as institutional OOB confirm.

---

## 6. Legal / ethical guardrails + honest limits

- **Consent + ownership:** scan only owned/authorized devices — unauthorized forensic scanning can be unlawful (wiretap/CFAA). MVT is consensual by design.
- **Detect, don't exploit:** ingest IOCs/artifacts only; never bundle exploit/implant/C2 code.
- **Stalkerware duty-of-care:** alerting the device can tip off an abuser and escalate danger — follow Coalition Against Stalkerware; surface a safety referral (Access Now / NNEDV) before any auto-removal. (Why TinyCheck is off-device.)
- **Anti-phishing rule:** a genuine Apple Threat Notification NEVER asks you to click a link, open a file, install anything, or share a password — confirm only at account.apple.com.
- **Source integrity + provenance:** attributable sources only; preserve report/feed + date per indicator; honor licenses (Amnesty CC-BY; abuse.ch terms; age out >6-month abuse.ch IOCs).
- **Privacy minimization:** forensic backups contain the user's whole life — process locally, minimize retention, encrypt at rest.
- **No fabrication in output:** never report a heuristic as a confirmed infection.
- **UNVERIFIED flags:** NoviSpy file-level IOCs; iOS-26 shutdown.log-erase mechanics; exact ATT&CK T-IDs for Cytrox/Predator; current Rayhunter device list; whether shreshta-labs/Gitea TinyCheck mirrors == Kaspersky upstream; NSA ANT/TAO catalog (not retrieved — don't cite from memory); ATT&CK Navigator exact live URL. Predator live Tier-1 IPs rotate — use Recorded Future's current list.
- **Disagreement noted:** behavioral side-channels — vendor consensus holds battery/heat/data as low-reliability mundane symptoms, NOT diagnostic; dumps converge that only a *persisting cluster* + OOB confirmation warrants action.

---

## 7. Consolidated Sources (deduped real URLs)

**Amnesty / MVT / forensics**
- https://securitylab.amnesty.org/latest/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/
- https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/
- https://www.amnesty.org/en/wp-content/uploads/2021/08/DOC1044872021ENGLISH.pdf
- https://securitylab.amnesty.org/latest/2023/10/technical-deep-dive-into-intellexa-alliance-surveillance-products/
- https://securitylab.amnesty.org/latest/2025/12/intellexa-leaks-predator-spyware-operations-exposed/
- https://securitylab.amnesty.org/latest/2024/12/serbia-a-digital-prison-spyware-and-cellebrite-used-on-journalists-and-activists/
- https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/
- https://securitylab.amnesty.org/tools-and-guides/
- https://www.amnesty.org/en/latest/news/2024/04/global-apple-threat-notifications-what-they-mean-and-what-you-can-do/
- https://github.com/mvt-project/mvt
- https://docs.mvt.re/en/latest/ios/records/
- https://docs.mvt.re/en/stable/iocs/
- https://docs.mvt.re/en/latest/introduction/
- https://mvt.re/
- https://github.com/mvt-project/mvt/blob/main/docs/iocs.md
- https://github.com/AmnestyTech/investigations
- https://github.com/AmnestyTech/investigations/tree/master/2021-07-18_nso
- https://github.com/AmnestyTech/investigations/blob/master/2021-07-18_nso/pegasus.stix2
- https://github.com/AmnestyTech/investigations/tree/master/2021-12-16_cytrox
- https://github.com/mvt-project/mvt-indicators/blob/main/indicators.yaml

**Citizen Lab**
- https://citizenlab.ca/2021/07/amnesty-peer-review/
- https://citizenlab.ca/research/forcedentry-nso-group-imessage-zero-click-exploit-captured-in-the-wild/
- https://citizenlab.ca/research/nso-groups-pegasus-spyware-returns-in-2022/
- https://citizenlab.ca/2023/04/nso-groups-pegasus-spyware-returns-in-2022/
- https://citizenlab.ca/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/
- https://citizenlab.ca/research/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/
- https://citizenlab.ca/research/predator-spyware-targets-us-eu-lawmakers-journalists/
- https://citizenlab.ca/research/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/
- https://citizenlab.ca/research/a-first-look-at-paragons-proliferating-spyware-operations/
- https://citizenlab.ca/research/spyware-vendor-quadream-exploits-victims-customers/
- https://citizenlab.ca/2014/06/backdoor-hacking-teams-tradecraft-android-implant/
- https://citizenlab.ca/2022/04/catalangate-extensive-mercenary-spyware-operation-against-catalans-using-pegasus-candiru/
- https://citizenlab.ca/2022/07/geckospy-pegasus-spyware-used-against-thailands-pro-democracy-movement/
- https://citizenlab.ca/2015/10/mapping-finfishers-continuing-proliferation/

**Microsoft / Google / vendors**
- https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/
- https://blogs.microsoft.com/on-the-issues/2021/07/15/cyberweapons-cybersecurity-sourgum-malware/
- https://socprime.com/blog/devilstongue-spyware-detection/
- https://blog.google/threat-analysis-group/0-days-exploited-by-commercial-surveillance-vendor-in-egypt/
- https://cloud.google.com/blog/topics/threat-intelligence/intellexa-zero-day-exploits-continue
- https://securelist.com/finspy-unseen-findings/104322/
- https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/
- https://support.eset.com/en/kb6558-eset-detects-and-stops-finfisher-also-known-as-finspy
- https://www.welivesecurity.com/2018/03/09/new-traces-hacking-team-wild/
- https://www.recordedfuture.com/research/predator-still-active-new-links-identified
- https://www.bleepingcomputer.com/news/security/whatsapp-patched-zero-day-flaw-used-in-paragon-spyware-attacks/
- https://github.com/4ARMED/volatility-attributeht
- https://cyberlaw.stanford.edu/blog/2021/05/i-have-lot-say-about-signals-cellebrite-hack/
- https://en.wikipedia.org/wiki/Cellebrite_UFED
- https://en.wikipedia.org/wiki/FinFisher

**MITRE ATT&CK**
- https://attack.mitre.org/matrices/mobile/
- https://attack.mitre.org/software/S0289/
- https://attack.mitre.org/software/S0316/
- https://github.com/mitre-attack/attack-stix-data
- https://mitre-attack.github.io/attack-navigator/
- https://attack.mitre.org/techniques/T1660/ · /T1451/ · /T1638/ · /T1566/001/ · /T1566/002/ · /T1598/004/ · /T1528/ · /T1557/
- https://attack.mitre.org/detectionstrategies/DET0515/

**Network-side / radio**
- https://github.com/shreshta-labs/TinyCheck-threat-detection-edition
- https://usa.kaspersky.com/about/press-releases/kaspersky-unveils-new-online-hub-for-tinycheck-stalkerware-detection-tool
- https://pts-project.org/docs/pirogue/architecture/
- https://pts-project.org/docs/pirogue/capture-network-traffic/
- https://pts-project.org/guides/g7/
- https://www.eff.org/pages/crocodile-hunter
- https://github.com/EFForg/crocodilehunter
- https://www.eff.org/deeplinks/2025/03/meet-rayhunter-new-open-source-tool-eff-detect-cellular-spying
- https://www.eff.org/deeplinks/2025/09/rayhunter-what-we-have-found-so-far
- https://github.com/EFForg/rayhunter
- https://sls.eff.org/technologies/cell-site-simulators-imsi-catchers
- https://seaglass.cs.washington.edu/
- https://techpolicylab.uw.edu/wp-content/uploads/2018/07/SeaGlass-Enabling-City-Wide-IMSI-Catcher-Detection.pdf
- https://onlinelibrary.wiley.com/doi/10.1155/2021/8847803
- https://www.vice.com/en/article/stingray-detection-apps-might-not-be-all-that-good-research-suggests/
- https://arxiv.org/pdf/2505.14509
- https://www.ndss-symposium.org/wp-content/uploads/2025-1115-paper.pdf
- https://github.com/activecm/rita
- https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/
- https://activecm.github.io/threat-hunting-labs/beacons/
- https://mohit.io/blog/windows-capture-analyze-mobile-device-network-traffic/

**Threat-intel feeds / aggregation / rules**
- https://threatfox.abuse.ch/export/ · https://threatfox.abuse.ch/faq/
- https://urlhaus.abuse.ch/api/
- https://bazaar.abuse.ch/export/
- https://auth.abuse.ch/
- https://github.com/opnsense/core/issues/6922
- https://www.misp-project.org/feeds/
- https://github.com/SigmaHQ/sigma
- https://github.com/InQuest/awesome-yara
- https://securityboulevard.com/2026/03/spyware-makers-in-2025-for-the-first-time-topped-googles-lists-of-zero-day-exploits/

**Deception / behavioral / consumer / hardening / help orgs**
- https://canarytokens.org/
- https://docs.canarytokens.org/guide/
- https://help.canary.tools/hc/en-gb/articles/4701687447325-What-are-Canarytokens
- https://blog.thinkst.com/2016/05/certified-canarytokens-alerts-from_25.html
- https://github.com/thinkst/canarytokens
- https://faculty.nps.edu/dedennin/publications/honeyfiles.pdf
- https://link.springer.com/chapter/10.1007/978-3-642-05284-2_4
- https://iverify.io/blog/iverify-mobile-threat-investigation-uncovers-new-pegasus-samples
- https://therecord.media/pegasus-spyware-infections-iverify
- https://support.apple.com/en-us/102174
- https://support.apple.com/en-us/105120
- https://support.apple.com/guide/security/lockdown-mode-security-sec2437264f0/web
- https://www.apple.com/newsroom/2022/07/apple-expands-commitment-to-protect-users-from-mercenary-spyware/
- https://www.magnetforensics.com/blog/understanding-the-security-impacts-of-ios-18s-inactivity-reboot/
- https://www.cisa.gov/resources-tools/resources/mobile-communications-best-practice-guidance
- https://www.cisa.gov/sites/default/files/2024-12/guidance-mobile-communications-best-practices.pdf
- https://www.kaspersky.com/resource-center/threats/how-to-tell-if-your-phone-camera-has-been-hacked
- https://www.bitdefender.com/en-us/blog/hotforsecurity/why-is-my-battery-draining-so-fast-13-causes-and-quick-fixes
- https://en.wikipedia.org/wiki/Pi-hole
- https://www.xda-developers.com/most-pi-hole-setups-leak-browsing-to-isp-encryption-layer-stops-it/
- https://www.accessnow.org/help/
- https://ssd.eff.org/
- https://stopstalkerware.org/
- https://www.eff.org/press/releases/eff-antivirus-companies-and-human-rights-groups-launch-coalition-combat-stalkerware
- https://www.eff.org/issues/security