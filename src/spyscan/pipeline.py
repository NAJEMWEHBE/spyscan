# src/spyscan/pipeline.py
from __future__ import annotations
from pathlib import Path
from spyscan.facts import Fact, image_path_of, make_key
from spyscan.collectors.base import exe_from_command
from spyscan.finding import Finding
from spyscan.diff import diff_facts
from spyscan.score import score_fact, no_resolvable_parent
from spyscan.rules.ioc import IOCMatcher
from spyscan.allowlist import Allowlist, script_host_args
from spyscan.enrich import signature as _signature
from spyscan.enrich import hashing as _hashing
from spyscan.resources import bundle_dir


def _default_allowlist_path() -> Path:
    """Frozen-aware default shipped allowlist: <repo>/config/allowlist.json in dev,
    the bundled copy under _MEIPASS when frozen. A missing file yields an empty
    allowlist, so this never crashes the scan. Only used when a caller passes no
    explicit allowlist (the service always does)."""
    return bundle_dir("config", "allowlist.json")

# Attrs of the signer result we copy onto a fact when enriching.
_SIGNER_ATTRS = ("signed", "verified", "trusted_ms", "signer")
# Attrs of the defender result we copy onto a fact when enriching.
_DEFENDER_ATTRS = ("defender_hit", "threat")
# Persistence-class fact kinds where a vanished baseline entry is notable (possible
# exfil-then-cleanup). Ephemeral kinds (process/connection/device_use) churn normally
# and are excluded to avoid a false-positive firehose. See candidate #05.
_PERSISTENCE_KINDS = frozenset({"autostart", "driver", "service", "scheduled_task"})


def observed_deltas(baseline_fact: Fact | None, f: Fact) -> dict:
    """Deliberate observed-vs-baseline comparison (ADR 0002 follow-up).

    ``observed`` is invisible to the baseline diff by design; these are the two
    places where a *delta* in volatile state is itself weak (+1) evidence:

    * process: single instance at baseline, multiple now -- a second copy of the
      same binary appeared (possible injected/masqueraded twin). Multi->multi
      churn (svchost 83->85) stays silent.
    * driver: Stopped at baseline, Running now -- a dormant driver activated.
      Manual-start drivers flip on demand, hence +1 not more.

    Returns derived attrs for score_fact. {} when the fact is new (no baseline
    entry) or the baseline predates ADR 0002 (observed loads as {}).
    """
    if baseline_fact is None:
        return {}
    out: dict = {}
    if f.kind == "process":
        b_n = baseline_fact.observed.get("instance_count")
        c_n = f.observed.get("instance_count")
        if b_n == 1 and isinstance(c_n, int) and c_n > 1:
            out["instances_grew"] = f"1->{c_n}"
    elif f.kind == "driver":
        b_state = (baseline_fact.observed.get("state") or "").strip().lower()
        c_state = (f.observed.get("state") or "").strip().lower()
        if c_state == "running" and b_state and b_state != "running":
            out["driver_started"] = True
    return out


def _procname_for(f: Fact) -> str:
    """Best candidate process/entry name to test against the IOC procname list.

    autoruns facts carry attrs['entry']; process facts label as 'name (pid N)'.
    """
    return f.attrs.get("entry") or f.label.split(" ")[0]


def _default_signer(path: str) -> dict:
    """Real, defaulted signer: thin wrapper over enrich.signature.authenticode.

    Never raises (authenticode swallows its own errors); returns unknown on any
    failure so a slow/failed signing call can never crash the scan.
    """
    try:
        return _signature.authenticode(path)
    except Exception:
        # unknown (None), not unsigned (False): a failed/slow signer must not be
        # penalized as unsigned by score_fact (see enrich.signature.authenticode).
        return {"signed": None, "verified": None, "trusted_ms": False, "signer": ""}


def _exe_path_for(f: Fact) -> str:
    """Resolvable on-disk image path for a fact, or '' if none.

    Services and tasks hold a COMMAND LINE (PathName / Task To Run), so the
    program is cut out of it first (audit #5)."""
    if f.kind == "scheduled_task":
        return exe_from_command(str(f.attrs.get("task_to_run") or ""))
    if f.kind == "service":
        return exe_from_command(image_path_of(f.attrs))
    return image_path_of(f.attrs)


def _is_enrich_candidate(finding: "Finding") -> bool:
    """Cheap-signal heuristic: is this fact worth the slow per-file signer call?

    A candidate is a process or persistence fact (autostart, service, task,
    driver -- audit #5) that already looks suspicious from the cheap signals:
    score >= 3, OR runs from temp, OR no resolvable parent, OR is a new fact
    that has a real exe path.
    """
    fact = finding.fact
    if fact.kind != "process" and fact.kind not in _PERSISTENCE_KINDS:
        return False
    a = fact.attrs
    if finding.score >= 3:
        return True
    if a.get("from_temp"):
        return True
    if fact.kind == "process" and no_resolvable_parent(fact):
        return True
    if a.get("is_new") and _exe_path_for(fact):
        return True
    if a.get("first_look") and _exe_path_for(fact):
        return True       # first look: every persistence image gets a signature check
    return False


# Where a script host's payload must not come from (first look, audit #18):
# user-writable folders, a network share, a URL, inline script or base64.
_PAYLOAD_PLACES = ("\\users\\", "\\programdata\\", "\\appdata\\", "\\temp\\",
                   "http://", "https://", "vbscript:", "javascript:")
_ENCODED_FLAGS = frozenset({"-e", "-ec", "-en", "-enc", "-encodedcommand"})


def _script_payload(a: dict) -> bool:
    """True when a script/proxy host is handed a payload from a user-writable or
    remote place (rundll32 with a System32 DLL is not; with a ProgramData one is)."""
    for args in script_host_args(a):
        low = args.lower()
        if low.startswith("\\\\") or " \\\\" in low or any(p in low for p in _PAYLOAD_PLACES):
            return True
        if any(t in _ENCODED_FLAGS for t in low.split()):
            return True
    return False


def _under_windir(path: str) -> bool:
    return (path or "").lower().replace("/", "\\").startswith(
        ("c:\\windows\\", "%windir%", "%systemroot%"))


def _apply_allowlist(a: dict, entity_key: str, allowlist: Allowlist,
                     observed: dict | None = None) -> None:
    """Set a['allowlisted']/a['allowlist_reason'] in place if the fact matches a
    user allowlist rule. score_fact treats this exactly like the Microsoft floor
    (known-bad always overrides), so it can never hide real malware.

    A process's command lines live in ``observed`` (volatile, never diffed) but
    the Microsoft floor must see them: an MS-signed powershell.exe running a
    payload is not "known good" (audit #4)."""
    attrs = dict(a)
    attrs.setdefault("entity_key", entity_key)
    if observed and observed.get("cmdlines"):
        attrs.setdefault("cmdlines", list(observed["cmdlines"]))
    ok, reason = allowlist.matches(attrs)
    if ok:
        a["allowlisted"] = True
        a["allowlist_reason"] = reason


def build_findings(baseline: list[Fact], current: list[Fact],
                   ioc: IOCMatcher, *, signer=None, defender=None,
                   max_enrich: int = 50, defender_max: int = 10,
                   log=print, allowlist=None, dns=None,
                   first_look: bool = False) -> list["Finding"]:
    """Mark is_new via baseline diff, enrich with IOC hits, score, then run a
    SCOPED + CAPPED signature/Defender enrichment pass over the most suspicious
    process/autostart facts and re-score just those.

    Args:
      signer:    callable(path)->{signed,verified,trusted_ms,signer}. Defaults to
                 a thin wrapper over enrich.signature.authenticode (real, but
                 only ever called for at most ``max_enrich`` candidates).
      defender:  callable(path)->{defender_hit,threat}, or None (off by default;
                 a heavy per-file MpCmdRun scan ~2 min each, so opt-in only).
      max_enrich: hard cap on signer/hash calls; surplus candidates are skipped
                 with a one-line notice (never a silent cap).
      defender_max: separate, tighter cap on the Defender scans -- only the most
                 -suspicious ``defender_max`` files STILL actionable after the
                 signature check are scanned; the rest log a skip notice.
      allowlist: an Allowlist of user known-good rules, or None to load the
                 shipped config/allowlist.json. A matched fact is flagged
                 allowlisted and floored to INFO by score_fact -- but ONLY when
                 no known-bad signal fires, so it can never hide real malware.

    A failed/slow signer or defender call is treated as 'unknown' (try/except),
    so enrichment can never crash the scan.

    IOC enrichment notes:
      * ioc_procname_hit  -- process name (or autoruns entry) vs implant-daemon list.
      * ioc_domain_hit    -- netconns carry remote IPs, not hostnames, so the
                            remote IP is mapped back to its names through ``dns``
                            (an enrich.dnscache.DnsCache; None = no cache) and each
                            name is tested (audit #13).
      * dns_lookup        -- a cached lookup of a listed domain that no connection
                            explains becomes its own finding.
    """
    if signer is None:
        signer = _default_signer
    if allowlist is None:
        allowlist = Allowlist.load(_default_allowlist_path())

    # first look (audit #18): no baseline at all -- nothing is new, nothing was
    # removed, and persistence is judged on absolute signals instead
    d = diff_facts([] if first_look else baseline, current)
    if first_look:
        d = {"added": [], "changed": [], "removed": []}
    new_keys = {f.entity_key for f in d["added"]} | {f.entity_key for f in d["changed"]}
    base_by_key = {} if first_look else {f.entity_key: f for f in baseline}

    # --- first pass: cheap signals only ---
    findings = []
    explained: set[str] = set()          # IOC names already shown on a connection
    for f in current:
        a = dict(f.attrs)
        a["is_new"] = f.entity_key in new_keys
        # observed deltas: volatile state is diff-blind, but two transitions are
        # deliberately read back as weak evidence (see observed_deltas)
        a.update(observed_deltas(base_by_key.get(f.entity_key), f))

        # IOC enrichment
        if a.get("remote_ip"):
            hit = _ioc_host_for(a["remote_ip"], ioc, dns)
            a["ioc_domain_hit"] = hit is not None
            if hit:
                a["ioc_domain"] = hit
                explained.add(hit)
        if f.kind in ("process", "autostart"):
            a["ioc_procname_hit"] = ioc.match_proc(_procname_for(f))
        if first_look and f.kind in _PERSISTENCE_KINDS:
            a["first_look"] = True
            if _script_payload(a):
                a["script_payload"] = True

        # user allowlist (floors to INFO in score_fact unless known-bad fires)
        _apply_allowlist(a, f.entity_key, allowlist, f.observed)

        enriched = Fact(f.collector, f.entity_key, f.kind, f.label, a, f.attack_id,
                        f.observed)
        r = score_fact(enriched)
        findings.append(Finding(fact=enriched, score=r["score"],
                                bucket=r["bucket"], reasons=r["reasons"],
                                attack_id=f.attack_id))

    # --- second pass: scoped + capped signature/Defender enrichment ---
    candidates = [fd for fd in findings if _is_enrich_candidate(fd)]
    if first_look:
        # ties: third-party images before Windows' own (nearly all Microsoft)
        candidates.sort(key=lambda x: (x.score, not _under_windir(_exe_path_for(x.fact))),
                        reverse=True)
    else:
        candidates.sort(key=lambda x: x.score, reverse=True)
    if len(candidates) > max_enrich:
        skipped = len(candidates) - max_enrich
        log(f"  [enrich] {len(candidates)} candidates, cap {max_enrich}: "
            f"skipping {skipped} (raise max_enrich to enrich more)")
        candidates = candidates[:max_enrich]

    # Defender is opt-in AND heavy (per-file MpCmdRun ~2 min), so it is capped hard
    # at defender_max -- the most-suspicious candidates first (list is score-desc).
    defender_used = defender_skipped = 0
    for fd in candidates:
        path = _exe_path_for(fd.fact)
        if not path:
            continue
        # %windir%\... and bare 'rundll32.exe' -> the real file, so the hash and
        # Defender see the same file the signer does (audit #10)
        path = _signature.resolve_image(path) or path
        a = fd.fact.attrs
        try:
            sig = signer(path)
            # A determinate probe (signed is True/False) replaces the cheap autoruns
            # signal. An UNKNOWN probe (signed is None: timeout/error) must NOT clobber
            # an existing determinate signal to None -- e.g. an autoruns '(Not verified)'
            # would lose its unsigned penalty. Failed probe = no probe: copy nothing.
            if sig.get("signed") is not None:
                for k in _SIGNER_ATTRS:
                    if k in sig:
                        a[k] = sig[k]
        except Exception:
            pass  # treat as unknown -- never crash the scan
        # hash enrichment: compute the file's sha256 so a user sha256/md5 allowlist
        # rule can match process/driver/service facts too (autoruns already ships a
        # hash from autorunsc). GATED on the allowlist actually having hash rules, so
        # it costs nothing by default -- the shipped allowlist has none, and the
        # known-bad hash-IOC engine was deliberately dropped, so allowlist is the
        # only consumer of sha256.
        if allowlist.sha256 and not a.get("sha256"):
            h = _hashing.sha256(path)
            if h:
                a["sha256"] = h
        # Defender: opt-in second opinion that CAN disagree with the signature (a
        # signed-but-abused binary should still be flagged), capped at defender_max
        # since each scan is ~2 min. Candidates are score-desc, so the cap keeps the
        # most-suspicious first.
        if defender is not None:
            if defender_used < defender_max:
                try:
                    dv = defender(path)
                    for k in _DEFENDER_ATTRS:
                        if k in dv:
                            a[k] = dv[k]
                except Exception:
                    pass
                defender_used += 1
            else:
                defender_skipped += 1
        # re-apply the allowlist: enrichment may have resolved a signer/sha that
        # now matches a signer/hash rule (path_globs already matched in pass 1).
        _apply_allowlist(a, fd.fact.entity_key, allowlist, fd.fact.observed)
        # re-score with the freshly-enriched attrs (interacts with FIX 1: a now-
        # signed temp app can be allowlisted; a now-flagged one escalates)
        r = score_fact(fd.fact)
        fd.score, fd.bucket, fd.reasons = r["score"], r["bucket"], r["reasons"]

    if defender_skipped:
        log(f"  [defender] scanned {defender_used} file(s) (cap {defender_max}); "
            f"skipped {defender_skipped} still-suspicious file(s) -- raise defender_max "
            f"to scan more")

    # removed persistence: a persistence entry present at baseline but gone now is a possible
    # exfil-then-cleanup signal (candidate #05). Scored low (+3 -> INFO alone) so benign uninstalls
    # stay silent; only a vanished entry that ALSO looks suspicious (unsigned/temp/known-bad) or is
    # not allowlisted-away climbs to REVIEW/ALERT. Ephemeral kinds are excluded. The allowlist floor
    # (ADR 0001) and known-bad override still apply because we route through _apply_allowlist + score_fact.
    for rf in d["removed"]:
        if rf.kind not in _PERSISTENCE_KINDS:
            continue
        a = dict(rf.attrs)
        a["removed_since_baseline"] = True
        a.pop("is_new", None)  # a removed entry is not "new"; drop any stale baseline flag
        _apply_allowlist(a, rf.entity_key, allowlist, rf.observed)
        gone = Fact(rf.collector, rf.entity_key, rf.kind, rf.label, a, rf.attack_id,
                    rf.observed)
        r = score_fact(gone)
        findings.append(Finding(fact=gone, score=r["score"], bucket=r["bucket"],
                                reasons=r["reasons"], attack_id=rf.attack_id))

    # a cached lookup of a listed domain with no connection that explains it:
    # something on this PC resolved a known C2 domain (audit #13)
    for name in sorted(dns.names if dns is not None else ()):
        if name in explained or not ioc.match_domain(name):
            continue
        a = {"name": name, "ioc_dns_hit": True}
        hit = Fact("dnscache", make_key("dnscache", name), "dns_lookup",
                   f"DNS lookup: {name}", a, "T1071")
        r = score_fact(hit)
        findings.append(Finding(fact=hit, score=r["score"], bucket=r["bucket"],
                                reasons=r["reasons"], attack_id="T1071"))

    return sorted(findings, key=lambda x: x.score, reverse=True)


def _ioc_host_for(remote_ip: str, ioc: IOCMatcher, dns) -> str | None:
    """The listed domain a remote IP belongs to, or None. A literal IP entry
    still matches; otherwise every cached name that resolved to it is tested."""
    if ioc.match_domain(remote_ip):
        return remote_ip
    names = dns.by_ip.get(remote_ip, ()) if dns is not None else ()
    for name in sorted(names):
        if ioc.match_domain(name):
            return name
    return None
