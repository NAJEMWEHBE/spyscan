# src/spyscan/rules/proxy_hosts.py
"""Microsoft-signed programs whose job is to run SOMETHING ELSE.

Their signature vouches for the program, not for the script, DLL, URL or
command line they are handed, so the Microsoft floor (allowlist.py) never
covers one of them when it is given arguments.

Source: the LOLBAS project (https://lolbas-project.github.io/, api/lolbas.json),
every executable in its "Execute" and "AWL Bypass" categories, checked against
the list on 2026-11-10. Added by hand: the PowerShell hosts and cmd (the
original script hosts), and certutil and curl (LOLBAS files them under
"Download": they fetch a payload for whatever runs next). Script and library
entries of LOLBAS (.vbs, .ps1, .dll...) are covered by SCRIPT_EXTENSIONS and by
the hosts that load them (rundll32, regsvr32...). Names are lower-case file
names as Windows runs them; when updating, add, never rename.
"""
from __future__ import annotations

# PowerShell hosts: their command-line flags are read for a payload (first look).
POWERSHELL_HOSTS = frozenset({
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "sqlps.exe", "sqltoolsps.exe",
})

PROXY_HOSTS = POWERSHELL_HOSTS | frozenset({
    # the original script/proxy hosts
    "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "curl.exe",
    # LOLBAS "Execute" / "AWL Bypass": Windows and .NET Framework
    "addinutil.exe", "applaunch.exe", "aspnet_compiler.exe", "at.exe", "atbroker.exe",
    "bash.exe", "bitsadmin.exe", "certoc.exe", "change.exe", "cmstp.exe", "conhost.exe",
    "control.exe", "customshellhost.exe", "devtoolslauncher.exe", "dfsvc.exe",
    "diantz.exe", "diskshadow.exe", "dnscmd.exe", "dxcap.exe", "explorer.exe",
    "extexport.exe", "forfiles.exe", "fsutil.exe", "ftp.exe", "gpscript.exe", "hh.exe",
    "ie4uinit.exe", "iediagcmd.exe", "ieexec.exe", "infdefaultinstall.exe",
    "installutil.exe", "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe",
    "mmc.exe", "mofcomp.exe", "msbuild.exe", "msconfig.exe", "msdt.exe", "msiexec.exe",
    "netsh.exe", "odbcconf.exe", "offlinescannershell.exe", "pcalua.exe", "pcwrun.exe",
    "pnputil.exe", "presentationhost.exe", "provlaunch.exe", "query.exe", "rasautou.exe",
    "regasm.exe", "register-cimprovider.exe", "regsvcs.exe", "reset.exe",
    "runexehelper.exe", "runonce.exe", "runscripthelper.exe", "schtasks.exe", "scp.exe",
    "scriptrunner.exe", "setres.exe", "settingsynchost.exe", "setupugc.exe", "sftp.exe",
    "sigverif.exe", "ssh.exe", "stordiag.exe", "syncappvpublishingserver.exe",
    "ttdinject.exe", "tttracer.exe", "unregmp2.exe", "verclsid.exe", "vsjitdebugger.exe",
    "wab.exe", "wbemtest.exe", "winfile.exe", "winget.exe", "wlrmdr.exe", "wmic.exe",
    "workfolders.exe", "write.exe", "wsb.exe", "wsl.exe", "wt.exe", "wuauclt.exe",
    "xwizard.exe",
    # LOLBAS "Execute" / "AWL Bypass": other Microsoft-signed tools (SDKs, Office,
    # Edge, Teams, Visual Studio, Sysinternals...)
    "acccheckconsole.exe", "adplus.exe", "agentexecutor.exe", "appcert.exe",
    "applauncher.exe", "appvlp.exe", "bginfo.exe", "cdb.exe", "coregen.exe", "csi.exe",
    "dbgsrv.exe", "defaultpack.exe", "devinit.exe", "dnx.exe", "dotnet.exe",
    "dotnet-counters.exe", "dotnet-trace.exe", "fsi.exe", "fsianycpu.exe",
    "intellitrace.exe", "logger.exe", "mftrace.exe",
    "microsoft.nodejstools.pressanykey.exe", "mpiexec.exe", "mscopilot.exe",
    "mscopilot_proxy.exe", "msdeploy.exe", "msedge.exe", "msedge_proxy.exe",
    "msedgewebview2.exe", "msxsl.exe", "ntsd.exe", "openconsole.exe", "pixtool.exe",
    "procdump.exe", "rcsi.exe", "remote.exe", "squirrel.exe", "te.exe", "teams.exe",
    "tracker.exe", "update.exe", "visualuiaverifynative.exe", "vsdiagnostics.exe",
    "vshadow.exe", "vsiisexelauncher.exe", "vslaunchbrowser.exe", "vsls-agent.exe",
    "vstest.console.exe", "wfc.exe", "wfmformat.exe", "windbg.exe", "xbootmgr.exe",
    "xbootmgrsleep.exe",
})

# A program that is itself a script, console file or package runs through an
# interpreter; with arguments it is a proxy like the hosts above.
SCRIPT_EXTENSIONS = frozenset({
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1",
    ".hta", ".sct", ".msc", ".cpl", ".msi", ".msp",
})
