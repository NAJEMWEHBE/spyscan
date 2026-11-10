# src/spyscan/allowlist.py
"""Owner of every known-good floor: user rules AND a built-in Microsoft rule.

A small, explicit set of rules that floor a benign fact toward INFO so the
user's own trusted software (their dev interpreters, signed vendor tools)
stops raising ALERTs. In addition to the user-editable rules, it now owns a
built-in, always-active *verified Microsoft-signed* floor folded here from
score.py (ADR 0001), so allowlist.py is the single home of the "which
known-good floors exist?" policy and the Microsoft floor is finally inspectable
(see builtin_rules()). It is a NON-security gate: scoring applies it ONLY when
no known-bad signal is present, so it can never hide real malware (see
score.py). Loading a missing file yields an empty *user* allowlist -- the
built-in Microsoft floor still applies -- and the scan never crashes on a
bad/absent config.

The Microsoft floor judges the program the way Windows runs it and the
signature probe verified it (variables expanded, the path normalised, the
command cut the way CreateProcess cuts it) and fails closed: a command it
cannot read with confidence gets no floor.
"""
from __future__ import annotations
import json
import ntpath
import os
import re
from fnmatch import fnmatch
from pathlib import Path

from spyscan.facts import IMAGE_PATH_ATTRS
from spyscan.collectors.base import CommandCut, expand_path, is_tempish, split_command
from spyscan.rules.proxy_hosts import POWERSHELL_HOSTS, PROXY_HOSTS, SCRIPT_EXTENSIONS

# Fact attrs that hold an on-disk image path (tested against path_globs). The ONE
# list lives in facts.py and is shared with the enrichment pass (audit #2).
_PATH_ATTRS = IMAGE_PATH_ATTRS
# Of those, the attrs a collector has already parsed down to a path. ``path`` is
# not one: a service keeps its whole PathName (a command line) there.
_PARSED_IMAGE_ATTRS = ("image_path", "exe", "image")

# Signer common names that ARE Microsoft's own code. Exact match, not "contains
# microsoft": the Hardware Compatibility Publisher (WHQL/attestation signing) and
# the 3rd Party Application Component cert sign OTHER vendors' code (malicious
# attestation-signed drivers exist), and any vendor can put "Microsoft" in its
# own name (audit #4).
_MS_SIGNER_CNS = frozenset({
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
    "microsoft windows early launch anti-malware publisher",
})
_CN_RE = re.compile(r'(?:^|,)\s*CN\s*=\s*("?)([^,"]+)\1', re.IGNORECASE)

# Folders under the Windows folder that ordinary users can write to (published
# AppLocker-bypass folder lists). A Microsoft binary copied there is not in a
# protected place.
_USER_WRITABLE_UNDER_WINDOWS = (
    "Temp", "Tasks", "tracing", "debug", "PLA", r"Registration\CRMLog",
    r"System32\Tasks", r"System32\Tasks_Migrated", r"System32\spool",
    r"System32\Microsoft\Crypto\RSA\MachineKeys", r"System32\com\dmp", r"System32\FxsTmp",
    r"SysWOW64\Tasks", r"SysWOW64\com\dmp", r"SysWOW64\FxsTmp",
    r"Microsoft.NET\Framework\v4.0.30319\Temporary ASP.NET Files",
    r"Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files",
)

# Why a Microsoft-signed fact got no floor: shown as its first-look reason.
REFUSED_UNREADABLE = ("Microsoft-signed program, but its command line cannot be read "
                      "with confidence")
REFUSED_OUTSIDE = ("Microsoft-signed program, but it runs from outside the Windows and "
                   "Program Files folders")
REFUSED_PAYLOAD = ("Microsoft-signed program, but it is a host that its command hands "
                   "something to run")
REFUSED_TEMP = ("Microsoft-signed program, but its command reaches into a temp/AppData "
                "folder")

_BAD_PATH_CHARS = frozenset('"*?<>|') | frozenset(chr(i) for i in range(32))

# The exact arguments Windows itself registers for a host that are not a
# payload: the Windows Installer service (msiserver) and Edge's own logon entry.
# Any other argument counts.
_KNOWN_BARE_INVOCATIONS = {
    "msiexec.exe": frozenset({"/v"}),
    "msedge.exe": frozenset({"--no-startup-window --win-session-start"}),
}


def is_microsoft_signer(signer: str) -> bool:
    """True if a signer string ('Microsoft Windows' or a full X.500 subject
    'CN=Microsoft Windows, O=...') names one of Microsoft's own signing certs."""
    s = str(signer or "").strip()
    m = _CN_RE.search(s)
    cn = m.group(2) if m else s
    return cn.strip().lower() in _MS_SIGNER_CNS


def _system_root() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("windir") or "C:\\Windows"


def _win_path(path: str) -> str | None:
    """The path Windows opens for ``path``: variables expanded, ``/`` and NT
    prefixes folded, trailing dots dropped from every folder and trailing dots
    and spaces from the file name (as Win32 does), ``::$DATA`` dropped. None
    when it cannot be read with confidence: a ``..`` or dots-only component, a
    stream name, a wildcard or quote. Never raises."""
    s = expand_path(path).strip().replace("/", "\\")
    low = s.lower()
    for prefix in ("\\\\?\\", "\\??\\", "\\\\.\\"):
        if low.startswith(prefix):
            s = s[len(prefix):]
            break
    if s.lower().startswith("\\systemroot\\"):
        s = _system_root() + s[len("\\systemroot"):]
    elif s.lower().startswith("system32\\"):            # driver ImagePath style
        s = ntpath.join(_system_root(), s)
    if not s or any(ch in _BAD_PATH_CHARS for ch in s):
        return None
    parts = s.split("\\")
    for i, part in enumerate(parts):
        if i == len(parts) - 1:
            if part.lower().endswith("::$data"):
                part = part[:-len("::$data")]
            part = part.rstrip(". ")
            if not part:
                return None
        elif part:
            if not part.rstrip("."):
                return None                             # '.', '..', '...'
            part = part.rstrip(".")
        if ":" in part and not (i == 0 and len(part) == 2 and part[0].isalpha()):
            return None
        parts[i] = part
    return ntpath.normpath("\\".join(parts))


def _exe_name(name: str) -> str:
    """'C:\\x\\Cmd.Exe' -> 'cmd.exe'; 'cmd' -> 'cmd.exe' (Windows adds .exe)."""
    base = ntpath.basename(name.strip()).lower()
    if base.endswith(".mui"):
        base = base[:-4]
    if base and "." not in base:
        base += ".exe"
    return base


def _is_host(names: set[str]) -> bool:
    return any(n in PROXY_HOSTS or ntpath.splitext(n)[1] in SCRIPT_EXTENSIONS
               for n in names if n)


def _in_system_folders(path: str) -> bool:
    """True when ``path`` (from _win_path) is in a folder only administrators
    can write to: the Windows folder (less its user-writable corners), Program
    Files, or the Defender platform folder. A bare program name counts: the
    signature probe looks it up in System32 and the Windows folder first."""
    if "\\" not in path:
        return True
    env = os.environ
    root = _system_root()
    data = env.get("ProgramData") or "C:\\ProgramData"
    inside = [root, ntpath.join(data, "Microsoft", "Windows Defender", "Platform")]
    inside += [env.get(k) or "" for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")]
    low = path.lower() + "\\"

    def under(folder: str) -> bool:
        return bool(folder) and low.startswith(ntpath.normpath(folder).lower().rstrip("\\") + "\\")

    if any(under(ntpath.join(root, sub)) for sub in _USER_WRITABLE_UNDER_WINDOWS):
        return False
    return any(under(f) for f in inside)


def _cut_is_sure(cut: CommandCut) -> bool:
    """True when the program of ``cut`` is the file Windows starts: an exact
    cut, or an unquoted path with a space whose shorter prefixes Windows tries
    first (``C:\\Program.exe``, ``C:\\Program Files\\Common.exe``) could only
    be planted by an administrator: in the system drive's root or a protected
    folder."""
    if cut.exact:
        return True
    if not cut.skipped:
        return False
    drive = os.environ.get("SystemDrive") or ntpath.splitdrive(_system_root())[0] or "C:"
    drive_root = drive.rstrip("\\").lower() + "\\"
    for prefix in cut.skipped:
        tried = _win_path(prefix + ".exe")
        if tried is None or "\\" not in tried:
            return False
        in_root = ntpath.dirname(tried).lower().rstrip("\\") + "\\" == drive_root
        if not in_root and not _in_system_folders(tried):
            return False
    return True


def _is_bare(names: set[str], args: str) -> bool:
    """True when ``args`` is a host's known harmless invocation (or nothing)."""
    said = " ".join(args.lower().split())
    return not said or any(said in _KNOWN_BARE_INVOCATIONS.get(n, ()) for n in names)


def _cut_launch(cmd: str, image: str) -> CommandCut:
    """Cut one command line. When it starts with the fact's own image (a
    process's command line starts with its exe), the rest is the arguments."""
    c = cmd.strip()
    if image:
        for spelled in (image, '"' + image + '"'):
            if c.lower().startswith(spelled.lower()):
                rest = c[len(spelled):]
                if spelled[0] == '"' or not rest or rest[0] in " \t":
                    return CommandCut(image, rest.strip(), True)
    return split_command(c)


def _command_view(attrs: dict) -> tuple[str, bool, list[str], list[CommandCut]]:
    """(image, exact, commands, launches): the program a fact runs, whether
    that is certain, and every command line that may hand it arguments, raw
    and cut.

    An image a collector already parsed (``image_path``, ``exe``, ``image``) is
    taken as it is. A task holds its command in ``task_to_run`` and a service
    in ``path`` (the whole PathName): there the program is cut out of the
    command the same way the signature probe cuts it (pipeline._exe_path_for),
    so the floor and the signature judge the same file."""
    image = ""
    for key in _PARSED_IMAGE_ATTRS:
        image = str(attrs.get(key) or "").strip()
        if image:
            break
    exact = True
    commands = [str(attrs.get("launch_string") or "")] + [
        str(c) for c in (attrs.get("cmdlines") or [])]
    run = str(attrs.get("task_to_run") or "").strip() or (
        "" if image else str(attrs.get("path") or "").strip())
    if run:
        commands.append(run)
        if not image:
            cut = split_command(run)
            image, exact = cut.program, _cut_is_sure(cut)
    commands = [c for c in commands if c.strip()]
    return image, exact, commands, [_cut_launch(c, image) for c in commands]


def _host_launches(attrs: dict) -> tuple[str | None, list[tuple[set[str], CommandCut | None]]]:
    """(refusal, hosts). ``refusal`` says why the program itself cannot stand
    for what the signature verified (unreadable, or outside the protected
    folders), else None. ``hosts`` is every launch that runs a script/proxy
    host, with the host's names; a launch whose program cannot be read is
    listed with None (it may be one)."""
    image, exact, _commands, launches = _command_view(attrs)
    target = str(attrs.get("signed_image") or "").strip() or image
    path = _win_path(target) if target else ""
    image_path = _win_path(image) if image else ""
    refusal = None
    if path is None or image_path is None or not exact:
        refusal = REFUSED_UNREADABLE
    elif path and not _in_system_folders(path):
        refusal = REFUSED_OUTSIDE
    names = {_exe_name(str(attrs.get("original_filename") or "")),
             _exe_name(path or ""), _exe_name(image_path or "")} - {""}
    image_host = _is_host(names)
    hosts: list[tuple[set[str], CommandCut | None]] = []
    for cut in launches:
        lpath = _win_path(cut.program) if cut.program else ""
        if lpath is None:
            hosts.append((names, None))
            continue
        lnames = {_exe_name(lpath)} - {""}
        if image_host or _is_host(lnames):
            hosts.append((names | lnames, cut))
    return refusal, hosts


def microsoft_floor(attrs: dict) -> tuple[bool, str]:
    """The built-in known-good floor (ADR 0001): (True, '') when a fact is
    verified Microsoft-signed AND runs only itself; (False, why) when it is
    Microsoft-signed but the floor is refused; (False, '') when it is not
    Microsoft-signed at all.

    Verified-gating is load-bearing: an UNVERIFIED fact whose signer merely
    claims 'Microsoft' must NOT floor (spoofed-cert bypass). The cross-collector
    `or` stays (enriched facts set trusted_ms; autoruns facts set verified+signer
    but not trusted_ms).

    "Runs only itself" fails closed. The program must be readable, sit in a
    folder only administrators can write to, and when it is a script or proxy
    host (by its file name or the OriginalFilename the enrichment read from the
    verified file, so a renamed copy is still known) every launch must be that
    bare program: any argument, or a command the cut cannot account for,
    refuses the floor. A launch reaching into a temp/AppData folder the image is
    not in refuses it too. Never raises: an error refuses the floor."""
    signed_by_ms = bool(attrs.get("trusted_ms")) or bool(
        attrs.get("verified") and is_microsoft_signer(attrs.get("signer", "")))
    if not signed_by_ms:
        return False, ""
    try:
        refusal, hosts = _host_launches(attrs)
        if refusal:
            return False, refusal
        for names, cut in hosts:
            if cut is None or not _cut_is_sure(cut):
                return False, REFUSED_UNREADABLE
            if not _is_bare(names, cut.args):
                return False, REFUSED_PAYLOAD
        image, _exact, commands, _launches = _command_view(attrs)
        if not is_tempish(image) and any(is_tempish(c) for c in commands):
            return False, REFUSED_TEMP
        return True, ""
    except Exception:
        return False, REFUSED_UNREADABLE


def script_host_args(attrs: dict) -> list[tuple[str, str]]:
    """(host, arguments) for each launch that hands a script/proxy host
    (powershell, cmd, rundll32...) arguments, variables expanded; [] when there
    is none. ``host`` is a PowerShell host's name when any name of the program
    is one. Used by first look (#18). Never raises."""
    try:
        _refusal, hosts = _host_launches(attrs)
        out = []
        for names, cut in hosts:
            if cut is None or not cut.args:
                continue
            named = sorted(names)
            host = ([n for n in named if n in POWERSHELL_HOSTS] or named or [""])[0]
            out.append((host, expand_path(cut.args)))
        return out
    except Exception:
        return []


def _is_ms_signed(attrs: dict) -> bool:
    """True if the built-in Microsoft floor applies (see microsoft_floor)."""
    return microsoft_floor(attrs)[0]


class Allowlist:
    def __init__(self, signers=None, path_globs=None, sha256=None, entity_keys=None):
        # signers: substring match, case-insensitive
        self.signers = [s.lower() for s in (signers or []) if s]
        # path_globs: fnmatch over a lowercased image path
        self.path_globs = [g.lower() for g in (path_globs or []) if g]
        # sha256: a hash set (also tested against a fact's md5), case-insensitive
        self.sha256 = {h.lower() for h in (sha256 or []) if h}
        # entity_keys: exact namespaced-key match
        self.entity_keys = set(entity_keys or [])

    @classmethod
    def load(cls, path) -> "Allowlist":
        """Load rules from a JSON file. A missing/unreadable/malformed file
        returns an empty allowlist (never raises) so the scan can't crash."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return cls()
        if not isinstance(data, dict):
            return cls()
        return cls(
            signers=data.get("signers"),
            path_globs=data.get("path_globs"),
            sha256=data.get("sha256"),
            entity_keys=data.get("entity_keys"),
        )

    def matches(self, attrs: dict) -> tuple[bool, str]:
        """Return (True, "allowlisted: <rule + value>") if any rule matches the
        fact's attrs, else (False, "")."""
        # path_globs over exe/image_path (lowercased fnmatch)
        for key in _PATH_ATTRS:
            val = (attrs.get(key) or "").strip()
            if not val:
                continue
            low = val.lower()
            for g in self.path_globs:
                if fnmatch(low, g):
                    return True, f"allowlisted: path_glob '{g}' matched {val}"

        # signer substring
        signer = str(attrs.get("signer") or "")
        if signer:
            sl = signer.lower()
            for s in self.signers:
                if s in sl:
                    return True, f"allowlisted: signer '{s}' in {signer}"

        # sha256 / md5 against the hash set
        for hkey in ("sha256", "md5"):
            h = str(attrs.get(hkey) or "").lower()
            if h and h in self.sha256:
                return True, f"allowlisted: {hkey} {h}"

        # entity_key exact
        ek = attrs.get("entity_key")
        if ek and ek in self.entity_keys:
            return True, f"allowlisted: entity_key {ek}"

        # built-in known-good floor: verified Microsoft-signed (ADR 0001, folded from score.py).
        # Always active -- even for an empty/missing user allowlist -- so it preserves the old
        # unconditional score.py floor. score.py applies it only when no known-bad signal fires.
        if _is_ms_signed(attrs):
            return True, "allowlisted: Microsoft-signed"
        return False, ""

    def builtin_rules(self) -> list[str]:
        """Human-readable built-in (non-user-editable) known-good rules, for CLI/app
        display. Currently: the verified Microsoft-signed floor folded from score.py (ADR 0001)."""
        return ["Microsoft-signed (verified), in the Windows or Program Files folders, "
                "and not a script/proxy host handed something to run"]
