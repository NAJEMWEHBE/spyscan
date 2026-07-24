# tests/test_score.py
from spyscan.facts import Fact
from spyscan.score import score_fact, Bucket


def test_bucket_owns_actionability_policy():
    # Bucket is the single home of 'which verdicts do we surface?'
    assert Bucket.ALERT.is_actionable and Bucket.REVIEW.is_actionable
    assert not Bucket.INFO.is_actionable
    # Bucket.for_score() maps score -> Bucket member (and StrEnum keeps == "ALERT" true)
    assert Bucket.for_score(8) is Bucket.ALERT and Bucket.for_score(8) == "ALERT"
    assert Bucket.for_score(4) is Bucket.REVIEW and Bucket.for_score(0) is Bucket.INFO


def temp_proc():
    return Fact("processes", "processes::u.exe::u.exe", "process", "u.exe",
                {"from_temp": True, "signed": False, "trusted_ms": False, "is_new": True})


def test_temp_unsigned_new_alerts():
    r = score_fact(temp_proc())
    assert r["score"] >= 8 and Bucket.for_score(r["score"]) == "ALERT"
    assert "runs from temp" in " ".join(r["reasons"]).lower()


def test_bucket_boundaries():
    assert Bucket.for_score(8) == "ALERT" and Bucket.for_score(4) == "REVIEW" and Bucket.for_score(3) == "INFO"


# --- FIX 1: a known-bad signal must OVERRIDE the Microsoft allowlist floor ---
# MS-signed malware (stolen cert / LOLBin / signed implant) must not be floored
# to INFO when Defender or an IOC fires. The allowlist only applies when NO
# known-bad signal is present.

def test_trusted_ms_with_defender_hit_is_not_info():
    f = Fact("processes", "processes::x::x", "process", "x",
             {"trusted_ms": True, "verified": True, "signer": "Microsoft Windows",
              "defender_hit": True})
    r = score_fact(f)
    assert r["bucket"] != "INFO"
    assert r["score"] >= 4  # at least REVIEW


def test_trusted_ms_with_ioc_procname_hit_is_not_info():
    f = Fact("processes", "processes::x::x", "process", "x",
             {"trusted_ms": True, "verified": True, "signer": "Microsoft Windows",
              "ioc_procname_hit": True})
    r = score_fact(f)
    assert r["bucket"] != "INFO"


def test_score_fact_does_not_floor_raw_ms_without_allowlisted():
    # post ADR 0001: score.py no longer floors a Microsoft fact by itself -- the allowlist
    # (via the pipeline) sets attrs['allowlisted']; score.py only honors that flag.
    f = Fact("processes", "processes::x::x", "process", "x",
             {"trusted_ms": True, "verified": True, "signer": "Microsoft Windows",
              "is_new": True, "from_temp": True})
    r = score_fact(f)
    assert r["bucket"] != "INFO"   # scores is_new(+3)+from_temp(+3); not floored here


# --- user allowlist: floors to INFO ONLY when no known-bad signal (mirrors the
# Microsoft rule -- known-bad always overrides, so the allowlist can't hide
# real malware). The pipeline sets attrs['allowlisted'] + allowlist_reason. ---

def test_allowlisted_no_known_bad_is_info():
    f = Fact("processes", "processes::p::p", "process", "p",
             {"is_new": True, "from_temp": True, "verified": False,
              "allowlisted": True, "allowlist_reason": "allowlisted: path_glob x"})
    r = score_fact(f)
    assert r["bucket"] == "INFO" and r["score"] == 0
    assert "allowlisted: path_glob x" in r["reasons"]


def test_allowlisted_but_defender_hit_is_not_info():
    # known-bad overrides the user allowlist -- proves it can't hide real malware
    f = Fact("processes", "processes::p::p", "process", "p",
             {"is_new": True, "from_temp": True, "allowlisted": True,
              "allowlist_reason": "allowlisted: path_glob x", "defender_hit": True})
    r = score_fact(f)
    assert r["bucket"] != "INFO"
    assert any("defender" in w.lower() for w in r["reasons"])


def test_allowlisted_but_ioc_procname_hit_is_not_info():
    f = Fact("processes", "processes::p::p", "process", "p",
             {"allowlisted": True, "allowlist_reason": "allowlisted: path_glob x",
              "ioc_procname_hit": True})
    r = score_fact(f)
    assert r["bucket"] != "INFO"


def test_allowlisted_reason_defaults_when_missing():
    f = Fact("processes", "processes::p::p", "process", "p",
             {"is_new": True, "allowlisted": True})
    r = score_fact(f)
    assert r["bucket"] == "INFO" and r["score"] == 0
    assert any("allowlisted" in w.lower() for w in r["reasons"])


# --- individual scoring branches ---

def test_is_new_alone_is_review_floor():
    f = Fact("autoruns", "autoruns::a::b", "autostart", "X", {"is_new": True})
    r = score_fact(f)
    assert "+3 new since baseline" in r["reasons"]


def test_unsigned_branch():
    f = Fact("autoruns", "autoruns::a::b", "autostart", "X", {"verified": False})
    r = score_fact(f)
    assert any("unsigned" in why.lower() for why in r["reasons"])


def test_unknown_signature_is_not_penalized_as_unsigned():
    # #12: unknown (None) signature -- the probe timed out/failed -- must NOT add
    # the "+2 unsigned" penalty. A temp+new binary with an UNKNOWN signature is
    # REVIEW (3+3=6), not ALERT (>=8): a failed probe scores the same as no probe.
    f = Fact("processes", "processes::u::u", "process", "u",
             {"from_temp": True, "is_new": True, "signed": None, "verified": None})
    r = score_fact(f)
    assert not any("unsigned" in w.lower() for w in r["reasons"])
    assert r["bucket"] != "ALERT"


def test_no_parent_only_for_process():
    proc = Fact("processes", "processes::x::x", "process", "x", {"parent": ""})
    conn = Fact("netconns", "netconns::x::y", "connection", "x", {"parent": ""})
    assert any("no resolvable parent" in w for w in score_fact(proc)["reasons"])
    assert not any("no resolvable parent" in w for w in score_fact(conn)["reasons"])


def test_ioc_domain_hit_branch():
    f = Fact("netconns", "netconns::x::y", "connection", "x",
             {"remote_ip": "13.37.13.37", "ioc_domain_hit": True})
    r = score_fact(f)
    assert any("c2 domain" in w.lower() or "mercenary" in w.lower() for w in r["reasons"])


def test_ioc_procname_hit_branch():
    f = Fact("processes", "processes::bh::bh", "process", "bh", {"ioc_procname_hit": True})
    r = score_fact(f)
    assert any("implant daemon" in w.lower() for w in r["reasons"])


def test_webcam_in_use_branch():
    f = Fact("consentstore", "consentstore::webcam::app", "device_use", "webcam: app",
             {"capability": "webcam", "in_use_now": True})
    r = score_fact(f)
    assert any("webcam/mic in use" in w.lower() for w in r["reasons"])


def test_hidden_flag_branch():
    f = Fact("processes", "processes::x::x", "process", "x", {"hidden_flag": True})
    r = score_fact(f)
    assert any("hidden-window" in w.lower() for w in r["reasons"])


def test_defender_hit_branch():
    f = Fact("processes", "processes::x::x", "process", "x", {"defender_hit": True})
    r = score_fact(f)
    assert any("defender" in w.lower() for w in r["reasons"])
    assert r["score"] >= 5


# --- loopback / ephemeral netconn churn must score 0 (benign) ---

def _conn(remote_ip):
    # a NEW connection (would otherwise get +3) used to prove loopback floors to 0
    return Fact("netconns", f"netconns::p::{remote_ip}", "connection",
                f"p -> {remote_ip}",
                {"remote_ip": remote_ip, "is_new": True, "listening": False})


def test_loopback_ipv4_connection_is_benign():
    r = score_fact(_conn("127.0.0.1"))
    assert r["score"] == 0 and Bucket.for_score(r["score"]) == "INFO"


def test_loopback_ipv4_whole_range_is_benign():
    r = score_fact(_conn("127.5.6.7"))
    assert r["score"] == 0 and r["bucket"] == "INFO"


def test_loopback_ipv6_is_benign():
    r = score_fact(_conn("::1"))
    assert r["score"] == 0


def test_link_local_is_benign():
    r = score_fact(_conn("169.254.10.20"))
    assert r["score"] == 0


def test_empty_remote_connection_is_benign():
    f = Fact("netconns", "netconns::p::listen", "connection", "p (listen)",
             {"remote_ip": "", "is_new": True, "listening": True})
    r = score_fact(f)
    assert r["score"] == 0


def test_new_connection_to_public_ip_still_scores_is_new():
    # a NEW connection to a PUBLIC ip is NOT floored — it keeps its is_new weight
    r = score_fact(_conn("13.37.13.37"))
    assert r["score"] >= 3
    assert any("new since baseline" in w.lower() for w in r["reasons"])


# --- canary trip: a tripped honeyfile is a HIGH-confidence behavioral signal.
# It is treated like a known-bad (+8 -> ALERT on its own) and, exactly like the
# IOC-hash path, it must NOT be silenced by the user allowlist -- something
# reading/modifying a decoy the user never created is spyware behavior, full stop.

def test_canary_trip_alerts_on_its_own():
    f = Fact("canary", "canary::C:/Desktop/passwords.txt", "canary_trip",
             "canary tripped: passwords.txt", {"canary_tripped": True})
    r = score_fact(f)
    assert r["bucket"] == "ALERT"
    assert r["score"] >= 8
    assert any("canary" in w.lower() for w in r["reasons"])


def test_canary_trip_alerts_even_when_allowlisted():
    # a canary trip is known-bad-class: the allowlist must never floor it to INFO
    f = Fact("canary", "canary::C:/Desktop/passwords.txt", "canary_trip",
             "canary tripped: passwords.txt",
             {"canary_tripped": True, "allowlisted": True,
              "allowlist_reason": "allowlisted: path_glob *"})
    r = score_fact(f)
    assert r["bucket"] == "ALERT"
    assert r["score"] >= 8


def test_canary_trip_alerts_even_when_ms_signed_floor():
    # likewise a Microsoft-signed attr set must not silence a canary trip
    f = Fact("canary", "canary::C:/Desktop/passwords.txt", "canary_trip",
             "canary tripped: passwords.txt",
             {"canary_tripped": True, "trusted_ms": True, "verified": True,
              "signer": "Microsoft Windows"})
    r = score_fact(f)
    assert r["bucket"] == "ALERT"


def test_untripped_canary_attr_does_not_alert():
    # defensive: a canary_tripped=False attr must not score
    f = Fact("canary", "canary::x", "canary_trip", "x", {"canary_tripped": False})
    r = score_fact(f)
    assert r["bucket"] == "INFO"


# --- ADR 0001 follow-on / candidate #05: removed-since-baseline persistence signal ---
def test_removed_alone_is_info_low_fp():
    # removed alone (+3) = INFO: a benign uninstall of a signed entry must not spam REVIEW/ALERT
    f = Fact("services_tasks", "services_tasks::s::s", "service", "Svc",
             {"removed_since_baseline": True, "verified": True})
    r = score_fact(f)
    assert r["bucket"] == "INFO"
    assert any("removed since baseline" in w.lower() for w in r["reasons"])


def test_removed_plus_unsigned_is_review():
    # corroborated: removed(+3) + unverified(+2) = 5 -> REVIEW
    f = Fact("autoruns", "autoruns::a::b", "autostart", "X",
             {"removed_since_baseline": True, "verified": False})
    r = score_fact(f)
    assert r["bucket"] == "REVIEW"


def test_removed_ms_signed_is_floored_to_info():
    # a removed Microsoft-signed persistence entry (benign MS uninstall) -> INFO via allowlist floor
    f = Fact("autoruns", "autoruns::a::b", "autostart", "X",
             {"removed_since_baseline": True, "verified": True, "signer": "Microsoft Windows",
              "allowlisted": True, "allowlist_reason": "allowlisted: Microsoft-signed"})
    r = score_fact(f)
    assert r["bucket"] == "INFO" and r["score"] == 0
