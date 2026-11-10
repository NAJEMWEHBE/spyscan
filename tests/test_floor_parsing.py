"""The command cut and the identity read the Microsoft floor relies on, and a
seeded fuzz: a crafted command line must never make the floor raise (an
exception there is a scanner an attacker can stop)."""
from __future__ import annotations
import random

import pytest

from spyscan.allowlist import (Allowlist, _host_launches, _win_path, microsoft_floor,
                               script_host_args)
from spyscan.collectors.base import CommandCut, is_tempish, split_command
from spyscan.enrich.peinfo import original_filename
from spyscan.pipeline import _script_payload


@pytest.mark.parametrize("cmd,cut", [
    ("", CommandCut("", "", True)),
    ("cmd /c x", CommandCut("cmd", "/c x", True)),
    ('"C:\\W\\cmd.exe"/c x', CommandCut("C:\\W\\cmd.exe", "/c x", True)),
    ('"C:\\W\\cmd.exe" /c x', CommandCut("C:\\W\\cmd.exe", "/c x", True)),
    ('"C:\\W\\cmd.exe /c x', CommandCut("C:\\W\\cmd.exe /c x", "", False)),
    ("C:\\ProgramData\\a.cmd \\..\\sc.exe", CommandCut("C:\\ProgramData\\a.cmd", "\\..\\sc.exe", True)),
    ("C:\\Program Files\\A\\a.exe -k", CommandCut("C:\\Program Files\\A\\a.exe", "-k", False,
                                                  ("C:\\Program",))),
    ("C:\\Program Files\\My App\\a.exe", CommandCut("C:\\Program Files\\My App\\a.exe", "", False,
                                                    ("C:\\Program", "C:\\Program Files\\My"))),
    ("C:\\W\\cmd /c x", CommandCut("C:\\W\\cmd", "/c x", False)),
    ("\tsc.exe\t", CommandCut("sc.exe", "", True)),
])
def test_split_command_cuts_like_createprocess(cmd, cut):
    assert split_command(cmd) == cut


@pytest.mark.parametrize("raw,norm", [
    ("C:\\Windows\\System32\\cmd.exe. . ", "C:\\Windows\\System32\\cmd.exe"),
    ("C:/Windows/System32/cmd.exe::$DATA", "C:\\Windows\\System32\\cmd.exe"),
    ("C:\\Windows.\\System32\\cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
    ("\\??\\C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
    ("C:\\Windows \\System32\\cmd.exe", "C:\\Windows \\System32\\cmd.exe"),
    ("C:\\x\\..\\cmd.exe", None),
    ("C:\\x\\a.txt:evil.exe", None),
    ("C:\\x\\*.exe", None),
])
def test_win_path_reads_a_path_the_way_win32_opens_it(raw, norm):
    assert _win_path(raw) == norm


def test_original_filename_of_something_that_is_not_a_pe_is_empty(tmp_path):
    junk = tmp_path / "x.exe"
    junk.write_bytes(b"MZ" + b"\x00" * 10)
    assert original_filename(str(junk)) == ""
    assert original_filename(str(tmp_path / "missing.exe")) == ""
    assert original_filename("") == ""


_PIECES = ['"', "'", " ", "\t", "\\", "/", ".", "..", ":", "::$DATA", "%", "%ComSpec%",
           "%TEMP%", "$", ",", "-", "/c", "-enc", "-c", "\u2013", "\x00", "\u00e9", "C:",
           "\\\\?\\", "\\??\\", "cmd.exe", "powershell", "rundll32.exe", "msiexec.exe",
           "Program Files", "Windows", "System32", "x", "*", "?", "|", "<", ">", "~1",
           "\\SystemRoot\\", "System32\\", "\U0001f600", "\r\n"]
_KEYS = ["task_to_run", "path", "image_path", "exe", "launch_string", "signed_image",
         "original_filename"]


def _crafted(rng: random.Random) -> str:
    return "".join(rng.choice(_PIECES) for _ in range(rng.randint(0, 14)))


def test_crafted_command_lines_never_make_the_floor_raise():
    rng = random.Random(20261110)
    al = Allowlist()
    for _ in range(4000):
        attrs = {"trusted_ms": True, "verified": True, "signer": "Microsoft Windows"}
        for key in rng.sample(_KEYS, rng.randint(1, 4)):
            attrs[key] = _crafted(rng)
        if rng.random() < 0.3:
            attrs["cmdlines"] = [_crafted(rng) for _ in range(rng.randint(0, 3))]
        text = _crafted(rng)
        # the unguarded internals first, so a bug is not hidden by the fail-closed guard
        split_command(text)
        _win_path(text)
        is_tempish(text)
        _host_launches(attrs)
        ok, why = microsoft_floor(attrs)
        assert isinstance(ok, bool) and isinstance(why, str)
        assert isinstance(al.matches(attrs)[0], bool)
        assert isinstance(script_host_args(attrs), list)
        assert isinstance(_script_payload(attrs), bool)
