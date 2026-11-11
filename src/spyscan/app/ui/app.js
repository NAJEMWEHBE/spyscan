/* spyscan desktop app -- vanilla fetch, no dependencies, no build step. */
"use strict";

const $ = (id) => document.getElementById(id);

const scanBtn   = $("scanBtn");
const scanHint  = $("scanHint");
const spinner   = scanBtn.querySelector(".spinner");
const btnLabel  = scanBtn.querySelector(".btn-label");
const reportBtn = $("reportBtn");
const baselineBtn = $("baselineBtn");

const verdict      = $("verdict");
const verdictIcon  = $("verdictIcon");
const verdictTitle = $("verdictTitle");
const verdictSub   = $("verdictSub");

const findingsBody = $("findingsBody");
const findingsMeta = $("findingsMeta");
const emptyState   = $("emptyState");

const DOT = String.fromCharCode(0x00b7);   // middle dot separator (ASCII source)
const TICK = String.fromCharCode(0x2713);  // check mark (ASCII source)

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function getJSON(url) {
  const r = await fetch(url);
  return r.json();
}
// The local server only answers JSON POSTs (a cross-site "simple request" can't
// send application/json without a preflight it never approves).
async function postJSON(url) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  // A reply that says OK but cannot be read is not a success and not a failure:
  // the result is unknown (failureMessage says so).
  const unread = r.ok
    ? { ok: false, unread: true, error: "the local service's reply could not be read" }
    : {};
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => unread) };
}
// Why a postJSON result failed ("" when it did not): postJSON never throws on an
// HTTP error, so every caller must check this before reporting success.
function postError({ ok, status, data }) {
  if (ok && !(data && data.ok === false)) return "";
  return data && data.error ? String(data.error) : `HTTP ${status}`;
}
// What to show for a postJSON result that is not a success ("" when it is one).
// After an unreadable OK reply the action may have worked, so the text says the
// result is unknown and points at the state the panel has just re-read, not at
// a retry (a second deploy would plant more decoys).
function failureMessage(res, failed, unknown) {
  const err = postError(res);
  if (!err) return "";
  return res.data && res.data.unread
    ? `The local service's reply could not be read, so it is not known whether ${unknown}. ` +
      "Check what is shown here before trying again."
    : `${failed} (${err}).`;
}

/* ---------- status / baseline / allowlist ---------- */

async function refreshStatus() {
  let s;
  try { s = await getJSON("/api/status"); }
  catch (e) { $("baselineStatus").textContent = "Could not reach the local service."; return; }

  // baseline panel
  if (s.baseline_exists) {
    let when = s.last_scan && s.last_scan.when ? `, last scan ${esc(s.last_scan.when)}` : "";
    $("baselineStatus").innerHTML =
      `Baseline set &mdash; <strong>${esc(s.baseline_count)}</strong> trusted facts${when}.`;
    baselineBtn.textContent = "Re-set baseline (trusted machine)";
  } else {
    $("baselineStatus").innerHTML =
      "No baseline yet. <span class='muted'>Set one on a trusted machine first.</span>";
  }

  // allowlist panel
  if (s.allowlist) {
    const c = s.allowlist.counts || {};
    const total = (c.path_globs||0) + (c.signers||0) + (c.sha256||0) + (c.entity_keys||0);
    $("allowlistStatus").innerHTML =
      `<strong>${total}</strong> allowlist rule${total === 1 ? "" : "s"} active ` +
      `<span class="muted">(${c.path_globs||0} paths, ${c.signers||0} signers, ` +
      `${c.sha256||0} hashes, ${c.entity_keys||0} keys)</span>`;
    $("allowlistPath").textContent = s.allowlist.path || "config/allowlist.json";
  }

  // report button enabled only if a scan has run
  reportBtn.disabled = !(s.last_scan);
}

/* ---------- canary tripwires ---------- */

async function refreshCanary() {
  let d;
  try { d = await getJSON("/api/canary/status"); }
  catch (e) { $("canaryStatus").textContent = "Could not reach the local service."; return; }

  const list = $("canaryList");
  const meta = $("canaryMeta");
  const clearBtn = $("canaryClearBtn");

  if (!d.deployed) {
    $("canaryStatus").innerHTML =
      "No decoys deployed. <span class='muted'>Plant some to catch an implant that snoops your files.</span>";
    list.hidden = true; list.innerHTML = "";
    meta.textContent = "";
    clearBtn.disabled = true;
    $("canaryAuditBtn").disabled = true;
    $("canaryAudit").hidden = true;
    return;
  }

  clearBtn.disabled = false;
  $("canaryAuditBtn").disabled = false;
  const n = d.canaries.length;
  if (d.tripped > 0) {
    $("canaryStatus").innerHTML =
      `<strong class="trip">${d.tripped} of ${n} decoy${n === 1 ? "" : "s"} TRIPPED</strong> ` +
      `<span class="muted">- something accessed a decoy. Run a scan for the ALERT detail.</span>`;
  } else {
    $("canaryStatus").innerHTML =
      `<strong>${n}</strong> decoy${n === 1 ? "" : "s"} armed ${DOT} ` +
      `<span class="muted">none tripped (all untouched).</span>`;
  }
  meta.textContent = `${n} armed ${DOT} ${d.tripped} tripped`;

  list.innerHTML = "";
  for (const c of d.canaries) {
    const li = document.createElement("li");
    li.className = c.tripped ? "trip" : "ok";
    const mark = c.tripped ? "TRIPPED" : TICK;
    const who = (c.accessed_by || []).length ? " (accessed by " + esc(c.accessed_by.join(", ")) + ")" : "";
    const why = c.tripped ? " - " + esc((c.reasons || []).join(", ")) + who : "";
    li.innerHTML = `<span class="canary-mark">${mark}</span> ${esc(c.path)}${why}`;
    list.appendChild(li);
  }
  list.hidden = false;
}

async function doCanaryDeploy() {
  const btn = $("canaryDeployBtn");
  if (!confirm("Plant decoy honeyfiles on this machine's Desktop, Documents, and app folder?\n\n" +
               "They are harmless fakes. Clear them when done.")) return;
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = "Planting...";
  try {
    const res = await postJSON("/api/canary/deploy");
    btn.textContent = old; btn.disabled = false;
    await refreshCanary();
    const failed = failureMessage(res, "Could not deploy decoys", "the decoys were planted");
    if (failed) {
      $("canaryStatus").textContent = failed;
      return;
    }
    const { data } = res;
    $("canaryStatus").innerHTML =
      `Planted <strong>${data.planted || 0}</strong> decoy file${(data.planted === 1) ? "" : "s"}. ` +
      `<span class="muted">Now run scans normally - a trip shows as an ALERT.</span>`;
  } catch (e) {
    btn.textContent = old; btn.disabled = false;
    $("canaryStatus").textContent = "Could not deploy decoys (local service error).";
  }
}

async function doCanaryClear() {
  const btn = $("canaryClearBtn");
  if (!confirm("Remove all decoy honeyfiles and the canary state?")) return;
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = "Clearing...";
  try {
    const failed = failureMessage(await postJSON("/api/canary/clear"),
                                  "Could not clear the decoys", "the decoys were removed");
    // Enabled again before the refresh: refreshCanary sets it from the real
    // state, and leaves it alone when the status cannot be read.
    btn.textContent = old; btn.disabled = false;
    await refreshCanary();
    if (failed) $("canaryStatus").textContent = failed + " Some may still be on disk.";
  } catch (e) {
    btn.textContent = old; btn.disabled = false;
    $("canaryStatus").textContent = "Could not clear the decoys (local service error).";
  }
}

async function doCanaryAudit() {
  let d;
  try { d = await getJSON("/api/canary/audit-setup"); }
  catch (e) { $("canaryStatus").textContent = "Could not reach the local service."; return; }
  if (!d.deployed) { $("canaryAudit").hidden = true; return; }
  $("canaryAuditCmds").textContent = d.commands;
  $("canaryAudit").hidden = false;
}

async function doCanaryAuditCopy() {
  const btn = $("canaryAuditCopyBtn");
  try {
    await navigator.clipboard.writeText($("canaryAuditCmds").textContent);
    btn.textContent = "Copied";
  } catch (e) {
    btn.textContent = "Select the text and copy it";
  }
  setTimeout(() => { btn.textContent = "Copy commands"; }, 2000);
}

/* ---------- verdict ---------- */

function showVerdict(summary) {
  let bucket, title, sub, icon;
  if (summary.alert > 0) {
    bucket = "ALERT"; icon = "!";
    title = `${summary.alert} alert finding${summary.alert === 1 ? "" : "s"}`;
    sub = "High-confidence suspicious activity. Review the rows below carefully.";
  } else if (summary.review > 0) {
    bucket = "REVIEW"; icon = "?";
    title = `${summary.review} item${summary.review === 1 ? "" : "s"} to review`;
    sub = "Worth a look. No high-confidence spyware signal.";
  } else {
    bucket = "CLEAN"; icon = TICK;
    title = "No high-risk findings";
    sub = "Device likely clean - but a clean result is not proof (see limits).";
  }
  verdict.className = "verdict " + bucket;
  verdictIcon.textContent = icon;
  verdictTitle.textContent = title;
  verdictSub.textContent = sub;
  verdict.hidden = false;
}

/* ---------- findings table ---------- */

function renderFindings(findings, summary) {
  findingsBody.innerHTML = "";
  if (!findings.length) {
    emptyState.hidden = false;
    findingsMeta.textContent =
      `0 high-risk ${DOT} ${summary.info} info ${DOT} ${summary.allowlisted} allowlisted`;
    return;
  }
  emptyState.hidden = true;
  findingsMeta.textContent =
    `${findings.length} shown ${DOT} ${summary.info} info ${DOT} ${summary.allowlisted} allowlisted`;

  for (const f of findings) {
    const fact = f.fact || {};
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td><span class="pill ${esc(f.bucket)}">${esc(f.bucket)} ${esc(f.score)}</span></td>` +
      `<td class="cell-entity">${esc(fact.label)}</td>` +
      `<td class="cell-src">${esc(fact.collector)}</td>` +
      `<td class="cell-why">${esc((f.reasons || []).join(", "))}</td>` +
      `<td class="cell-attack">${esc(f.attack_id || "")}</td>`;
    findingsBody.appendChild(tr);
  }
}

/* ---------- actions ---------- */

function setScanning(on) {
  scanBtn.disabled = on;
  $("triageBtn").disabled = on;
  spinner.hidden = !on;
  btnLabel.textContent = on ? "Scanning..." : "Scan now";
  scanHint.textContent = on
    ? "Collecting processes, autostarts, connections, drivers... (~30-40s)"
    : "A full scan takes about 30-40 seconds.";
}

async function doScan(route = "/api/scan") {
  setScanning(true);
  verdict.hidden = true;
  try {
    const withDefender = document.getElementById("defenderToggle")?.checked;
    const { ok, status, data } = await postJSON(route + (withDefender ? "?defender=1" : ""));
    if (!ok || data.ok === false) {
      const msg = data && data.error ? data.error : `scan failed (HTTP ${status})`;
      scanHint.textContent = msg.includes("baseline")
        ? "No baseline yet - set a baseline first (panel below)."
        : "Scan failed: " + msg;
      setScanning(false);
      return;
    }
    showVerdict(data.summary);
    renderFindings(data.findings || [], data.summary);
    reportBtn.disabled = false;
    setScanning(false);
    scanHint.textContent = data.meta && data.meta.mode
      ? "Done (" + data.meta.mode + "). Full detail in the HTML report."
      : "Done. Full detail in the HTML report.";
  } catch (e) {
    setScanning(false);
    scanHint.textContent = "Scan failed: could not reach the local service.";
  }
}

async function doBaseline() {
  if (!confirm("Capture THIS machine's current state as the trusted baseline?\n\n" +
               "Only do this if you trust the device right now.")) return;
  baselineBtn.disabled = true;
  const old = baselineBtn.textContent;
  baselineBtn.textContent = "Saving baseline...";
  try {
    const failed = failureMessage(await postJSON("/api/baseline"),
                                  "Could not save the baseline", "the baseline was saved");
    baselineBtn.textContent = old;
    baselineBtn.disabled = false;
    await refreshStatus();
    if (failed) $("baselineStatus").textContent = failed;
  } catch (e) {
    baselineBtn.textContent = old;
    baselineBtn.disabled = false;
    $("baselineStatus").textContent = "Could not save the baseline (local service error).";
  }
}

scanBtn.addEventListener("click", () => doScan("/api/scan"));
$("triageBtn").addEventListener("click", () => doScan("/api/triage"));
baselineBtn.addEventListener("click", doBaseline);
// The report may open outside this window (no session cookie there), so the
// link carries the per-launch token the server set at the handshake.
function sessionToken() {
  const m = document.cookie.match(/(?:^|;\s*)spyscan_token=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}
reportBtn.addEventListener("click", () =>
  window.open("/api/report?t=" + encodeURIComponent(sessionToken()), "_blank"));
$("canaryDeployBtn").addEventListener("click", doCanaryDeploy);
$("canaryClearBtn").addEventListener("click", doCanaryClear);
$("canaryAuditBtn").addEventListener("click", doCanaryAudit);
$("canaryAuditCopyBtn").addEventListener("click", doCanaryAuditCopy);

refreshStatus();
refreshCanary();
