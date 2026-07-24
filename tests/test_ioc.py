from spyscan.rules.ioc import IOCMatcher
def test_domain_and_proc_hits():
    m = IOCMatcher(domains={"sec-flare.com"}, procnames={"roleaccountd"})
    assert m.match_domain("login.sec-flare.com") is True   # suffix match
    assert m.match_domain("apple.com") is False
    assert m.match_proc("roleaccountd") is True
    assert m.match_proc("explorer.exe") is False


def test_trailing_dot_feed_domain_matches():
    # #13: a feed entry in root-form FQDN ('evil-c2.com.') must still match. The
    # domain set was normalized with lstrip('.') (leading only) while hosts are
    # rstrip('.')-normalized, so a trailing-dot feed entry never matched anything.
    m = IOCMatcher(domains={"evil-c2.com."})
    assert m.match_domain("evil-c2.com") is True          # exact, both normalized
    assert m.match_domain("beacon.evil-c2.com") is True   # suffix still works
    assert m.match_domain("evil-c2.com.") is True         # trailing-dot host too


def test_empty_and_malformed_feed_entries_do_not_match():
    # a malformed all-dots/empty feed line normalizes to '' and must be dropped,
    # else an empty domain would spuriously match an empty host string.
    m = IOCMatcher(domains={"...", "", "  "})
    assert m.match_domain("") is False
    assert m.match_domain("anything.com") is False
