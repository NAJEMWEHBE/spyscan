# tests/test_pipeline.py
from spyscan.facts import Fact
from spyscan.rules.ioc import IOCMatcher
from spyscan.allowlist import Allowlist
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


def test_is_new_marked_from_diff():
    base = [Fact("processes", "processes::old::old", "process", "old", {"signed": True})]
    current = [
        Fact("processes", "processes::old::old", "process", "old", {"signed": True}),
        Fact("processes", "processes::new::new", "process", "new", {"signed": True}),
    ]
    m = IOCMatcher()
    findings = build_findings(base, current, m)
    by_key = {f.fact.entity_key: f for f in findings}
    assert by_key["processes::new::new"].fact.attrs["is_new"] is True
    assert by_key["processes::old::old"].fact.attrs["is_new"] is False


def test_findings_sorted_by_score_desc():
    base = []
    current = [
        Fact("processes", "processes::clean::clean", "process", "clean", {"signed": True}),
        Fact("processes", "processes::bh::bh", "process", "bh",
             {"signed": False, "from_temp": True}),
    ]
    m = IOCMatcher(procnames={"bh"})
    findings = build_findings(base, current, m)
    scores = [f.score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_ioc_domain_hit_enriched_for_connection():
    base = []
    # netconns carry IPs, not hostnames; match_domain is called against the IP
    # (best-effort until DNS/Phase-2). Use an IP literal present in the IOC set.
    current = [Fact("netconns", "netconns::p::1.2.3.4", "connection", "p -> 1.2.3.4",
                    {"remote_ip": "1.2.3.4", "is_new": True})]
    m = IOCMatcher(domains={"1.2.3.4"})
    findings = build_findings(base, current, m)
    top = findings[0]
    assert top.fact.attrs["ioc_domain_hit"] is True
    assert any("c2 domain" in r.lower() or "mercenary" in r.lower() for r in top.reasons)


# --- FIX 2: signature + Defender enrichment wired into the live pipeline ---
# build_findings now takes injectable signer/defender callables and a max_enrich
# cap, so we can prove the wiring without spawning PowerShell.

def _ms_signer(path):
    return {"signed": True, "verified": True, "trusted_ms": True,
            "signer": "Microsoft Windows"}


def _unsigned_signer(path):
    return {"signed": False, "verified": False, "trusted_ms": False, "signer": ""}


def _unknown_signer(path):
    # a timed-out / errored Authenticode probe (see enrich.signature.authenticode)
    return {"signed": None, "verified": None, "trusted_ms": False, "signer": ""}


def test_unknown_probe_does_not_clobber_autoruns_verified():
    # #12: an autostart fact Autoruns flagged '(Not verified)' that becomes an enrich
    # candidate but whose Authenticode probe is UNKNOWN (timeout) must KEEP its unsigned
    # signal -- an unknown probe must not overwrite a determinate prior value with None.
    base = []
    current = [Fact("autoruns", "autoruns::u::u", "autostart", "Updater",
                    {"exe": r"C:\ProgramData\u.exe", "verified": False, "is_new": True})]
    findings = build_findings(base, current, IOCMatcher(), signer=_unknown_signer)
    top = findings[0]
    assert top.fact.attrs["verified"] is False        # NOT clobbered to None
    assert any("unsigned" in r.lower() for r in top.reasons)


def test_unknown_probe_temp_process_is_not_alert():
    # #12 end-to-end: a NEW temp process whose signature probe is UNKNOWN scores
    # is_new+temp only (REVIEW), never gaining the +2 unsigned penalty -> not ALERT.
    base = []
    current = [Fact("processes", "processes::u::u", "process", "u",
                    {"exe": r"C:\Windows\Temp\u.exe", "from_temp": True,
                     "parent": "explorer.exe"})]
    findings = build_findings(base, current, IOCMatcher(), signer=_unknown_signer)
    top = findings[0]
    assert top.bucket != "ALERT"
    assert not any("unsigned" in r.lower() for r in top.reasons)


def test_signed_temp_process_enriched_floored_to_info():
    # a NEW temp process is suspicious from cheap signals (is_new + from_temp);
    # enrichment proves it's Microsoft-signed -> allowlisted to INFO/0.
    base = []
    current = [Fact("processes", "processes::svc::svc", "process", "svc",
                    {"exe": r"C:\Windows\Temp\svc.exe", "from_temp": True,
                     "parent": "services.exe"})]
    m = IOCMatcher()
    findings = build_findings(base, current, m, signer=_ms_signer)
    top = findings[0]
    assert top.bucket == "INFO" and top.score == 0
    assert top.fact.attrs["trusted_ms"] is True


def test_defender_flagged_candidate_escalates_overrides_allowlist():
    # signer says Microsoft-signed BUT defender flags it -> known-bad overrides the
    # allowlist (FIX 1) and the dormant Defender signal now fires.
    base = []
    current = [Fact("processes", "processes::imp::imp", "process", "imp",
                    {"exe": r"C:\Windows\Temp\imp.exe", "from_temp": True,
                     "parent": "explorer.exe"})]
    m = IOCMatcher()

    def _defender(path):
        return {"defender_hit": True, "threat": "Trojan:Win32/Meterpreter"}

    findings = build_findings(base, current, m,
                              signer=_ms_signer, defender=_defender)
    top = findings[0]
    assert top.bucket in ("REVIEW", "ALERT")
    assert top.fact.attrs["defender_hit"] is True
    assert any("defender" in r.lower() for r in top.reasons)


def test_enrich_cap_holds_and_emits_skip_notice(capsys):
    # 60 suspicious candidates, cap = 50 -> only 50 enriched, skip notice printed.
    base = []
    current = [Fact("processes", f"processes::p{i}::p{i}", "process", f"p{i}",
                    {"exe": fr"C:\Windows\Temp\p{i}.exe", "from_temp": True,
                     "parent": "explorer.exe"})
               for i in range(60)]
    m = IOCMatcher()

    calls = {"n": 0}

    def _counting_signer(path):
        calls["n"] += 1
        return _unsigned_signer(path)

    findings = build_findings(base, current, m,
                              signer=_counting_signer, max_enrich=50)
    assert calls["n"] == 50
    out = capsys.readouterr().out.lower()
    assert "skip" in out or "skipped" in out
    assert "10" in out  # 60 candidates - 50 cap = 10 skipped


# --- UNIT 3: user allowlist wired into the pipeline (floors before scoring,
# overridden by known-bad). Inject an Allowlist so we don't depend on the
# shipped config file. ---

def test_allowlisted_temp_proc_floored_to_info():
    # a NEW unsigned temp process would ALERT; a path_glob allowlist floors it.
    base = []
    current = [Fact("processes", "processes::py::py", "process", "py",
                    {"exe": r"F:\proj\.venv\Scripts\python.exe", "from_temp": True,
                     "parent": ""})]
    al = Allowlist(path_globs=[r"*\.venv\scripts\*"])
    findings = build_findings(base, current, IOCMatcher(),
                              signer=_unsigned_signer, allowlist=al)
    top = findings[0]
    assert top.bucket == "INFO" and top.score == 0
    assert top.fact.attrs["allowlisted"] is True
    assert any("allowlisted" in r.lower() for r in top.reasons)


def test_allowlisted_signer_substring_floored_to_info():
    base = []
    current = [Fact("processes", "processes::v::v", "process", "v",
                    {"exe": r"C:\Apps\vendor.exe", "is_new": True})]
    al = Allowlist(signers=["acme corp"])

    def _acme_signer(path):
        return {"signed": True, "verified": True, "trusted_ms": False,
                "signer": "Acme Corp, O=Acme"}

    findings = build_findings(base, current, IOCMatcher(),
                              signer=_acme_signer, allowlist=al)
    top = findings[0]
    assert top.bucket == "INFO" and top.score == 0
    assert any("acme" in r.lower() for r in top.reasons)


def test_allowlisted_sha256_floored_to_info():
    base = []
    current = [Fact("autoruns", "autoruns::a::b", "autostart", "Updater",
                    {"sha256": "cafebabe", "verified": False, "is_new": True})]
    al = Allowlist(sha256=["cafebabe"])
    findings = build_findings(base, current, IOCMatcher(), allowlist=al)
    top = findings[0]
    assert top.bucket == "INFO" and top.score == 0
    assert any("cafebabe" in r.lower() for r in top.reasons)


def test_defender_cap_holds_and_emits_skip_notice(capsys):
    # 15 suspicious candidates, defender_max=10 -> only 10 defender-scanned + notice.
    base = []
    current = [Fact("processes", f"processes::p{i}::p{i}", "process", f"p{i}",
                    {"exe": fr"C:\Windows\Temp\p{i}.exe", "from_temp": True,
                     "parent": "", "is_new": True})
               for i in range(15)]
    m = IOCMatcher()
    calls = {"n": 0}

    def _def(path):
        calls["n"] += 1
        return {"defender_hit": False, "threat": ""}

    build_findings(base, current, m, signer=_unsigned_signer,
                   defender=_def, defender_max=10)
    assert calls["n"] == 10                       # capped, not all 15
    out = capsys.readouterr().out.lower()
    assert "defender" in out and ("skip" in out or "skipped" in out)
    assert "5" in out                             # 15 - 10 = 5 skipped


def test_defender_scans_even_signed_candidate(capsys):
    # Defender is a SECOND opinion: a candidate the signer calls Microsoft-signed
    # must still be Defender-scanned (a signed-but-abused binary can be flagged).
    base = []
    current = [Fact("processes", "processes::s::s", "process", "s",
                    {"exe": r"C:\Windows\Temp\s.exe", "from_temp": True,
                     "parent": "explorer.exe", "is_new": True})]
    scanned = {"n": 0}

    def _def(path):
        scanned["n"] += 1
        return {"defender_hit": True, "threat": "Trojan:Win32/Test"}

    findings = build_findings(base, current, IOCMatcher(),
                              signer=_ms_signer, defender=_def)
    assert scanned["n"] == 1                       # scanned despite MS signature
    assert findings[0].fact.attrs["defender_hit"] is True


def test_sha256_allowlist_matches_process_via_hashing(tmp_path):
    # #03: hashing enrichment computes a process fact's sha256 so a user sha256
    # allowlist rule matches it too -- parity with autoruns (which already ships a
    # hash). Requires a real file on disk (hashing reads it).
    import hashlib
    f = tmp_path / "tool.exe"
    f.write_bytes(b"trusted-bytes")
    digest = hashlib.sha256(b"trusted-bytes").hexdigest()
    base = []
    current = [Fact("processes", "processes::t::t", "process", "t",
                    {"exe": str(f), "from_temp": True, "parent": "", "is_new": True})]
    al = Allowlist(sha256=[digest])
    findings = build_findings(base, current, IOCMatcher(),
                              signer=_unsigned_signer, allowlist=al)
    top = findings[0]
    assert top.fact.attrs["sha256"] == digest          # hashing computed it
    assert top.fact.attrs["allowlisted"] is True        # sha256 rule matched
    assert top.bucket == "INFO" and top.score == 0      # floored to INFO


def test_hashing_skipped_when_no_sha256_rules(tmp_path):
    # cost guard: with NO hash rules in the allowlist, hashing must NOT run (no
    # sha256 attr appears) -- it stays free by default.
    f = tmp_path / "tool.exe"
    f.write_bytes(b"whatever")
    base = []
    current = [Fact("processes", "processes::t::t", "process", "t",
                    {"exe": str(f), "from_temp": True, "parent": "", "is_new": True})]
    al = Allowlist(path_globs=[r"*\nomatch\*"])  # non-empty allowlist, but no sha256 rules
    findings = build_findings(base, current, IOCMatcher(),
                              signer=_unsigned_signer, allowlist=al)
    assert "sha256" not in findings[0].fact.attrs


def test_allowlisted_but_defender_hit_still_escalates():
    # known-bad overrides the allowlist even when a rule matched -- no bypass.
    base = []
    current = [Fact("processes", "processes::py::py", "process", "py",
                    {"exe": r"F:\proj\.venv\Scripts\python.exe", "from_temp": True,
                     "parent": "explorer.exe"})]
    al = Allowlist(path_globs=[r"*\.venv\scripts\*"])

    def _defender(path):
        return {"defender_hit": True, "threat": "Trojan:Win32/Test"}

    findings = build_findings(base, current, IOCMatcher(),
                              signer=_unsigned_signer, defender=_defender,
                              allowlist=al)
    top = findings[0]
    assert top.bucket in ("REVIEW", "ALERT")
    assert any("defender" in r.lower() for r in top.reasons)


def test_non_allowlisted_temp_proc_still_alerts():
    # allowlist must not over-broaden: an unrelated unsigned new temp proc ALERTs.
    base = []
    current = [Fact("processes", "processes::evil::evil", "process", "evil",
                    {"exe": r"C:\Windows\Temp\evil.exe", "from_temp": True,
                     "parent": ""})]
    al = Allowlist(path_globs=[r"*\.venv\scripts\*"])
    findings = build_findings(base, current, IOCMatcher(),
                              signer=_unsigned_signer, allowlist=al)
    top = findings[0]
    assert top.bucket == "ALERT"
    assert top.fact.attrs.get("allowlisted") is not True


def test_default_allowlist_loads_shipped_config_without_crash():
    # allowlist=None must load config/allowlist.json (or empty) and never crash.
    base = []
    current = [Fact("processes", "processes::x::x", "process", "x",
                    {"exe": r"C:\nowhere\x.exe", "signed": True})]
    findings = build_findings(base, current, IOCMatcher(), signer=_unsigned_signer)
    assert isinstance(findings, list)


def test_findings_are_typed_and_dict_shape_is_deleted():
    # Deletion test: build_findings returns Finding objects and the old dict
    # shape is GONE -- subscripting must fail loudly (no silent dict/shim left).
    import pytest
    from spyscan.finding import Finding
    base = []
    current = [Fact("processes", "processes::x::x", "process", "x", {"signed": True})]
    findings = build_findings(base, current, IOCMatcher())
    assert findings and all(isinstance(f, Finding) for f in findings)
    with pytest.raises(TypeError):
        _ = findings[0]["bucket"]


# --- ADR 0001: the Microsoft floor, now folded into the allowlist, still works
# end-to-end through the live pipeline (and is still overridden by known-bad). ---

def test_ms_signed_autoruns_fact_floors_to_info_via_builtin_allowlist():
    # end-to-end: a verified Microsoft autoruns fact floors to INFO via the built-in allowlist
    # rule (folded from score.py), even with an EMPTY user allowlist -- proving the fold
    # preserved the old pass-1 autoruns MS floor.
    base = []
    current = [Fact("autoruns", "autoruns::ms::ms", "autostart", "MsUpdate",
                    {"verified": True, "signer": "Microsoft Windows"})]
    findings = build_findings(base, current, IOCMatcher(), allowlist=Allowlist())
    top = findings[0]
    assert top.bucket == "INFO"
    assert top.fact.attrs["allowlisted"] is True


def test_ms_signed_but_defender_hit_still_not_info_end_to_end():
    # non-security gate: the built-in Microsoft floor can NEVER hide malware -- a defender hit
    # is known-bad and overrides it end-to-end, exactly as it overrides a user allowlist rule.
    base = []
    current = [Fact("autoruns", "autoruns::ms::ms", "autostart", "MsUpdate",
                    {"exe": r"C:\ProgramData\ms.exe", "verified": True,
                     "signer": "Microsoft Windows", "is_new": True})]

    def _defender(path):
        return {"defender_hit": True, "threat": "Trojan:Win32/Test"}

    findings = build_findings(base, current, IOCMatcher(),
                              signer=_ms_signer, defender=_defender,
                              allowlist=Allowlist())
    top = findings[0]
    # the fold DID run: the built-in MS rule set allowlisted (empty user allowlist, so nothing
    # else could) -- yet known-bad still overrides it to non-INFO. This assert also makes the
    # test discriminate the fold (without it, allowlisted is never set on this fact).
    assert top.fact.attrs.get("allowlisted") is True
    assert top.bucket != "INFO"
    assert any("defender" in r.lower() for r in top.reasons)


# --- candidate #05: removed persistence becomes a finding; ephemeral removed does not ---
def test_removed_persistence_unsigned_becomes_actionable_finding():
    base = [Fact("autoruns", "autoruns::HKCU::Evil", "autostart", "Evil",
                 {"verified": False, "exe": r"C:\Temp\evil.exe"})]
    current = []
    findings = build_findings(base, current, IOCMatcher(), allowlist=Allowlist())
    ev = [f for f in findings if f.fact.entity_key == "autoruns::HKCU::Evil"]
    assert ev, "removed unsigned autostart should produce a finding"
    assert ev[0].bucket in ("REVIEW", "ALERT")
    assert any("removed since baseline" in r.lower() for r in ev[0].reasons)


def test_removed_ephemeral_process_is_not_a_finding():
    base = [Fact("processes", "processes::x::x", "process", "x", {"exe": r"C:\x.exe"})]
    current = []
    findings = build_findings(base, current, IOCMatcher(), allowlist=Allowlist())
    assert not any(f.fact.entity_key == "processes::x::x" for f in findings), \
        "a vanished process is normal churn, must not surface"


def test_removed_ms_signed_persistence_is_info_via_allowlist_floor():
    base = [Fact("autoruns", "autoruns::ms::ms", "autostart", "MsUpd",
                 {"verified": True, "signer": "Microsoft Windows"})]
    current = []
    findings = build_findings(base, current, IOCMatcher(), allowlist=Allowlist())
    ms = [f for f in findings if f.fact.entity_key == "autoruns::ms::ms"]
    assert ms, "removed MS autostart still produces a finding object"
    assert ms[0].bucket == "INFO"
    assert ms[0].fact.attrs.get("allowlisted") is True
