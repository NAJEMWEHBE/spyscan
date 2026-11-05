"""Audit #22 (bug half): the IOC loader and the printed audit commands.

- An indented '  # comment' line was kept as an IOC entry, and the files were
  read in the locale code page instead of UTF-8.
- enable_audit_commands put canary paths inside '...' unescaped: a path with
  an ASCII or typographic single quote breaks out of the string the user pastes.
"""
from __future__ import annotations
import shutil
import subprocess

import pytest

from spyscan.canary_audit import enable_audit_commands
from spyscan.rules.ioc import IOCMatcher


def test_indented_comments_and_blank_lines_are_not_entries(tmp_path):
    (tmp_path / "mercenary_procnames.txt").write_text(
        "# header\n  # indented comment\n\t#tab comment\nbh\n   \nroleaccountd  \n",
        encoding="utf-8")
    m = IOCMatcher.from_dir(tmp_path)
    assert m.procnames == {"bh", "roleaccountd"}


def test_indicator_files_are_read_as_utf8(tmp_path):
    (tmp_path / "mercenary_domains.txt").write_text(
        "\ufeffexample.test\nb\u00fccher.example\n", encoding="utf-8")
    m = IOCMatcher.from_dir(tmp_path)
    assert m.match_domain("example.test")
    assert m.match_domain("b\u00fccher.example")


EVIL = "C:\\Users\\v\\Desktop\\a\u2019;Write-Output INJECTED;\u2019b'c.txt"


def test_audit_command_paths_double_every_single_quote_variant():
    text = enable_audit_commands([EVIL])
    assert "a\u2019\u2019;Write-Output INJECTED;\u2019\u2019b''c.txt" in text


_PARSE = r"""
$src = [Console]::In.ReadToEnd()
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$t, [ref]$e)
$cmds = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
  ForEach-Object { $_.GetCommandName() }
"errors=$($e.Count)"
"cmds=" + (($cmds | Sort-Object -Unique) -join ',')
"""


@pytest.mark.skipif(shutil.which("powershell") is None, reason="needs Windows PowerShell")
def test_powershell_parser_sees_no_injected_command():
    # PARSE ONLY (never runs the text): which commands would PowerShell execute?
    script = enable_audit_commands([EVIL])
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PARSE],
                         input=script.encode("utf-8"), capture_output=True, timeout=60)
    text = out.stdout.decode("utf-8", errors="replace")
    assert "errors=0" in text
    cmds = next(l for l in text.splitlines() if l.startswith("cmds=")).split("=", 1)[1]
    assert "Write-Output" not in cmds
    assert set(cmds.split(",")) <= {"auditpol", "Get-Acl", "New-Object", "Set-Acl"}
