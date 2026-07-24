from pathlib import Path

import pytest

from spyscan.collectors import autoruns
from spyscan.collectors.autoruns import _split_verified, parse, _resolve_autorunsc


# --- Fix 1: doubled verification prefix ---

def test_doubled_not_verified_prefix_fully_stripped():
    verified, signer = _split_verified("(Not verified) (Not Verified) Microsoft Corporation")
    assert verified is False
    assert signer == "Microsoft Corporation"

def test_single_not_verified_prefix_still_works():
    verified, signer = _split_verified("(Not verified) Some Vendor")
    assert verified is False
    assert signer == "Some Vendor"

def test_single_verified_prefix_still_works():
    verified, signer = _split_verified("(Verified) Microsoft Windows")
    assert verified is True
    assert signer == "Microsoft Windows"

def test_doubled_mixed_prefix_first_prefix_wins():
    # first prefix decides verified; both prefixes are stripped
    verified, signer = _split_verified("(Verified) (Not verified) Acme Co")
    assert verified is True
    assert signer == "Acme Co"


# --- Fix 2: entity_key includes image path (collision avoidance) ---

_HDR = ("Time,Entry Location,Entry,Enabled,Category,Profile,Description,"
        "Signer,Company,Image Path,Version,Launch String,MD5,SHA-1,"
        "PESHA-1,PESHA-256,SHA-256,IMP\n")

def _row(entry, loc, image):
    return (f'"","{loc}","{entry}","enabled","Logon","User","",'
            f'"(Not verified)","","{image}","","{image}","M","","","","S",""\n')

def test_same_location_entry_different_image_yields_two_facts():
    raw = (_HDR
           + _row("Updater", "HKCU\\Run", "C:\\Users\\a\\one.exe")
           + _row("Updater", "HKCU\\Run", "C:\\Users\\a\\two.exe")
           ).encode("utf-8")
    facts = parse(raw)
    keys = {f.entity_key for f in facts}
    assert len(facts) == 2
    assert len(keys) == 2


# --- Fix 3: frozen-aware autorunsc resolution + graceful degradation ---

def test_resolver_returns_a_path():
    # the resolver must always hand back a Path (existing or best-effort default),
    # never None -- so AUTORUNSC is always usable / testable. The name is normally
    # autorunsc64.exe (the best-effort default and the only bundled name), but a user
    # who installed the arch-detecting `autorunsc.exe` on PATH resolves to that name --
    # either is a legitimate user-provided binary.
    p = _resolve_autorunsc()
    assert isinstance(p, Path)
    assert p.name in ("autorunsc64.exe", "autorunsc.exe")
    assert isinstance(autoruns.AUTORUNSC, Path)


def test_gather_missing_binary_raises_not_crashes(monkeypatch, tmp_path):
    # resolution yields a non-existent path -> gather() raises a clean
    # FileNotFoundError (a guard), NOT a subprocess explosion.
    monkeypatch.setattr(autoruns, "_resolve_autorunsc",
                        lambda: tmp_path / "nope" / "autorunsc64.exe")
    with pytest.raises(FileNotFoundError):
        autoruns.gather()


def test_gather_resolves_fresh_not_the_import_time_constant(monkeypatch, tmp_path):
    """gather() must re-resolve, never trust the import-time AUTORUNSC constant.

    The packaged app is long-lived and scans in-process, so a user can install autorunsc
    between launch and scan. `autorunsc_available()` re-resolves on every call and
    `autostart_native` steps aside the instant it returns True -- so if gather() still
    pointed at the stale import-time path it would raise while native had already bowed
    out, and the scan would produce NO autostart facts from EITHER collector, with only a
    print() as warning (invisible in the windowed console=False build).
    """
    installed = tmp_path / "late" / "autorunsc64.exe"
    installed.parent.mkdir(parents=True)
    installed.write_bytes(b"MZ")                     # exists NOW; did not at import time
    monkeypatch.setattr(autoruns, "AUTORUNSC", tmp_path / "stale" / "autorunsc64.exe")
    monkeypatch.setattr(autoruns, "_resolve_autorunsc", lambda: installed)

    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        class _R:
            stdout = b""
        return _R()

    monkeypatch.setattr(autoruns.subprocess, "run", fake_run)
    autoruns.gather()                                # must NOT raise on the stale path
    assert seen["argv"][0] == str(installed)         # ran the freshly-resolved binary
    assert autoruns.autorunsc_available() is True    # and agrees with the step-aside probe


def test_missing_autoruns_does_not_kill_the_scan(monkeypatch, tmp_path):
    # the resilient collector loop must swallow a failing autoruns collector and
    # keep going (returns facts from the others / empty) -- never propagate.
    from spyscan import service
    from spyscan.collectors.base import ScanContext
    monkeypatch.setattr(autoruns, "_resolve_autorunsc",
                        lambda: tmp_path / "gone" / "autorunsc64.exe")
    warnings = []
    ctx = ScanContext(root=tmp_path, now=0.0)
    facts = service.collect_all(ctx, log=lambda m: warnings.append(m))
    # did not raise; and the autoruns failure was logged as a warning
    assert isinstance(facts, list)
    assert any("autoruns" in w for w in warnings)
