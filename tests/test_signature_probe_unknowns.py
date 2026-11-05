"""Audit #10: a probe that could not look at the file is UNKNOWN, not unsigned.

Get-AuthenticodeSignature prints just '|' when the file is missing, and the
scanner handed it relative names (Winlogon 'explorer.exe', 'rundll32.exe') and
unexpanded REG_EXPAND_SZ paths ('%windir%\\...'), so real Windows binaries took a
false +2 "unsigned". Paths are now expanded and resolved first; what still
cannot be found is never probed.
"""
from __future__ import annotations
import json
import subprocess
import types

import pytest

from spyscan.enrich import signature as sig


@pytest.mark.parametrize("line", ["|", "", "  ", "NotSupportedFileFormat|"])
def test_status_that_says_nothing_about_the_file_is_unknown(line):
    s = sig.parse_status(line)
    assert s["signed"] is None and s["verified"] is None
    assert s["trusted_ms"] is False


@pytest.mark.parametrize("line", ["NotSigned|", "HashMismatch|CN=X", "UnknownError|CN=Self"])
def test_a_real_negative_verdict_stays_unsigned(line):
    # UnknownError is what a self-signed implant's untrusted chain returns: keep the penalty
    s = sig.parse_status(line)
    assert s["signed"] is False and s["verified"] is False


@pytest.fixture
def fake_windows(tmp_path, monkeypatch):
    root = tmp_path / "Windows"
    (root / "System32").mkdir(parents=True)
    (root / "System32" / "rundll32.exe").write_bytes(b"MZ")
    (root / "explorer.exe").write_bytes(b"MZ")
    monkeypatch.setenv("SystemRoot", str(root))
    monkeypatch.setenv("windir", str(root))
    monkeypatch.setenv("PATH", str(root / "System32"))
    calls = []

    def fake_run(args, **kw):
        calls.append(json.loads(kw["input"].decode("ascii")))
        return types.SimpleNamespace(stdout=b"Valid|CN=Microsoft Windows, O=Microsoft Corporation",
                                     stderr=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return root, calls


def test_bare_name_is_resolved_against_system32(fake_windows):
    root, calls = fake_windows
    r = sig.authenticode("rundll32.exe")
    assert calls == [str(root / "System32" / "rundll32.exe")]
    assert r["signed"] is True


def test_bare_name_is_resolved_against_the_windows_dir(fake_windows):
    root, calls = fake_windows
    sig.authenticode("explorer.exe")
    assert calls == [str(root / "explorer.exe")]


def test_environment_variables_are_expanded(fake_windows):
    root, calls = fake_windows
    sig.authenticode("%windir%\\System32\\rundll32.exe")
    assert calls == [str(root / "System32" / "rundll32.exe")]


def test_a_file_that_cannot_be_found_is_unknown_and_never_probed(fake_windows):
    _root, calls = fake_windows
    r = sig.authenticode("C:\\nope\\gone.exe")
    assert calls == []
    assert r["signed"] is None and r["verified"] is None
