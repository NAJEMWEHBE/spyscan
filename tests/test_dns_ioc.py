"""Audit #13: the domain IOC list was compared against remote IPs, so it could
never match. Domains are now matched against the Windows DNS client cache:

- a connection whose remote IP was resolved from a listed domain gets the
  domain hit,
- a cached lookup of a listed domain with no live connection is its own
  REVIEW finding (something on this PC resolved a known C2 domain).

The DNS cache is never read here: tests pass a parsed cache or fake the adapter.
"""
from __future__ import annotations
import subprocess
from pathlib import Path

from spyscan import service
from spyscan.allowlist import Allowlist
from spyscan.enrich import dnscache
from spyscan.facts import Fact
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher

# Get-DnsClientCache | Select-Object Entry,Name,Data | ConvertTo-Csv -NoTypeInformation
CACHE_CSV = (
    '"Entry","Name","Data"\r\n'
    '"cdn.urlpush.net","cdn.urlpush.net","edge.example-cdn.net"\r\n'
    '"cdn.urlpush.net","edge.example-cdn.net","203.0.113.7"\r\n'
    '"www.example.org","www.example.org","198.51.100.4"\r\n'
    '"lookup.grayhornet.com","lookup.grayhornet.com","2001:db8::5"\r\n'
).encode("utf-8")

IOC = IOCMatcher(domains={"urlpush.net", "grayhornet.com"})
SEED = Fact("processes", "processes::seed", "process", "seed", {})


def _conn(ip):
    return Fact("netconns", f"netconns::app::{ip}:443", "connection", f"app -> {ip}:443",
                {"process": "app.exe", "remote_ip": ip, "listening": False})


def _findings(current, dns):
    return build_findings([SEED], [SEED] + current, IOC, signer=lambda p: {},
                          allowlist=Allowlist(), log=lambda *a: None, dns=dns)


def test_parse_maps_ips_to_every_name_in_the_chain():
    cache = dnscache.parse(CACHE_CSV)
    assert cache.by_ip["203.0.113.7"] == {"cdn.urlpush.net", "edge.example-cdn.net"}
    assert cache.by_ip["2001:db8::5"] == {"lookup.grayhornet.com"}
    assert "edge.example-cdn.net" in cache.names and "www.example.org" in cache.names


def test_parse_of_nothing_is_an_empty_cache():
    assert dnscache.parse(b"") == dnscache.DnsCache()


def test_a_connection_to_an_ip_resolved_from_a_listed_domain_hits():
    out = _findings([_conn("203.0.113.7")], dnscache.parse(CACHE_CSV))
    fd = next(f for f in out if f.fact.kind == "connection")
    assert fd.fact.attrs["ioc_domain_hit"] is True
    assert fd.fact.attrs["ioc_domain"] == "cdn.urlpush.net"
    assert "+3 connects to known mercenary/C2 domain" in fd.reasons


def test_a_connection_to_an_unlisted_host_does_not_hit():
    out = _findings([_conn("198.51.100.4")], dnscache.parse(CACHE_CSV))
    fd = next(f for f in out if f.fact.kind == "connection")
    assert not fd.fact.attrs.get("ioc_domain_hit")


def test_a_cached_lookup_with_no_connection_is_its_own_review_finding():
    out = _findings([], dnscache.parse(CACHE_CSV))
    dns = [f for f in out if f.fact.kind == "dns_lookup"]
    names = sorted(f.fact.attrs["name"] for f in dns)
    assert names == ["cdn.urlpush.net", "lookup.grayhornet.com"]
    assert all(f.bucket == "REVIEW" for f in dns)


def test_a_lookup_already_shown_on_a_connection_is_not_repeated():
    out = _findings([_conn("203.0.113.7")], dnscache.parse(CACHE_CSV))
    names = sorted(f.fact.attrs["name"] for f in out if f.fact.kind == "dns_lookup")
    assert names == ["lookup.grayhornet.com"]


def test_without_a_cache_nothing_changes():
    out = _findings([_conn("203.0.113.7")], None)
    assert sorted(f.fact.kind for f in out) == ["connection", "process"]


def test_gather_reads_the_cache_through_the_powershell_adapter(monkeypatch):
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=CACHE_CSV, stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    cache = dnscache.gather()
    assert calls and calls[0][0] == "powershell" and "Get-DnsClientCache" in calls[0][-1]
    assert "203.0.113.7" in cache.by_ip


def test_gather_failure_is_an_empty_cache(monkeypatch):
    def boom(*a, **k):
        raise OSError("no powershell")

    monkeypatch.setattr(subprocess, "run", boom)
    assert dnscache.gather() == dnscache.DnsCache()


def _ind(tmp_path):
    d = tmp_path / "ind"
    d.mkdir()
    (d / "mercenary_domains.txt").write_text("urlpush.net\n", encoding="utf-8")
    (d / "mercenary_procnames.txt").write_text("", encoding="utf-8")
    return d


def test_run_scan_uses_an_injected_cache(tmp_path):
    db = tmp_path / "b.db"
    service.run_baseline(tmp_path, db, collect=lambda ctx: [SEED])
    res = service.run_scan(tmp_path, db, collect=lambda ctx: [SEED], ind=_ind(tmp_path),
                           dns=lambda: dnscache.parse(CACHE_CSV))
    assert [f.fact.attrs["name"] for f in res["findings"] if f.fact.kind == "dns_lookup"] \
        == ["cdn.urlpush.net"]


def test_run_scan_reads_the_live_cache_by_default_even_with_cli_collectors(
        tmp_path, monkeypatch):
    # the CLI always passes collect=..., so the default must still read the cache
    monkeypatch.setattr(service, "_live_dns", lambda: dnscache.parse(CACHE_CSV))
    db = tmp_path / "b.db"
    service.run_baseline(tmp_path, db, collect=lambda ctx: [SEED])
    res = service.run_scan(tmp_path, db, collect=lambda ctx: [SEED], ind=_ind(tmp_path))
    assert [f.fact.attrs["name"] for f in res["findings"] if f.fact.kind == "dns_lookup"]         == ["cdn.urlpush.net"]


def test_site_does_not_promise_stalkerware_lists_that_do_not_ship():
    site = (Path(__file__).resolve().parents[1] / "docs" / "index.html").read_text(encoding="utf-8")
    assert "stalkerware indicator lists" not in site
