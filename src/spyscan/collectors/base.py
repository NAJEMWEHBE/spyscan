from __future__ import annotations
import csv
import io
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from spyscan.facts import Fact

# Temp-ish path fragments: an image/exe/launch path containing one of these runs
# from a user-writable, low-trust location (%TEMP%, AppData) -- a strong "not a
# normally-installed program" signal. SINGLE SOURCE OF TRUTH: every collector
# derives its ``from_temp`` attr from is_tempish(), so the heuristic is spelled once.
_TEMPISH = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\appdata\\roaming\\")


def expand_path(text: str) -> str:
    """``text`` with its environment variables expanded the way the signature
    probe expands a path (``enrich.signature.resolve_image``): tasks and
    services keep raw ``%TEMP%`` / ``%ComSpec%`` / ``%windir%`` in their
    commands, and a test on the raw text never sees the folder they name.
    Unknown variables stay as written. Never raises."""
    s = str(text or "")
    try:
        return os.path.expandvars(s)
    except Exception:
        return s


def is_tempish(path: str) -> bool:
    """True if ``path`` sits under a temp/AppData location (case-insensitive),
    environment variables expanded first."""
    low = expand_path(path).lower().replace("/", "\\")
    return any(t in low for t in _TEMPISH)


def _oem_codepage() -> int | None:
    """The console (OEM) code page Windows tools like schtasks write in."""
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetOEMCP())
    except Exception:
        return None


def decode_console(raw: bytes) -> str:
    """Decode a Windows console tool's output (audit #12).

    UTF-8 when it is valid UTF-8 (incl. pure ASCII, so English output decodes
    exactly as before), otherwise the OEM code page (cp437/850/720...), which is
    what schtasks/driverquery write on a non-English system.
    """
    raw = raw or b""
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    cp = _oem_codepage()
    if cp:
        try:
            return raw.decode(f"cp{cp}", errors="replace")
        except LookupError:
            pass
    return raw.decode("utf-8", errors="replace")


def has_csv_column(raw: bytes, column: str) -> bool:
    """True when the first CSV row of a console tool's output names ``column``.

    schtasks/driverquery localize their headers, so a missing English column
    means "this Windows is not English" -> use the PowerShell fallback (#12).
    """
    text = decode_console(raw).lstrip()
    if not text:
        return False
    header = next(csv.reader(io.StringIO(text)), [])
    return column in (h.strip() for h in header)


def exe_from_command(cmd: str) -> str:
    """Best-effort image path out of a launch command (Run value, service
    PathName, task action).

    ``"C:\\Program Files\\App\\a.exe" -x`` -> ``C:\\Program Files\\App\\a.exe``
    ``C:\\Windows\\system32\\userinit.exe,`` -> ``C:\\Windows\\system32\\userinit.exe``
    ``rundll32.exe foo,Bar``                 -> ``rundll32.exe``
    Returns "" for an empty command. Never raises.
    """
    c = (cmd or "").strip()
    if not c:
        return ""
    if c[0] == '"':
        end = c.find('"', 1)
        return c[1:end] if end > 0 else c[1:]
    low = c.lower()
    idx = low.find(".exe")
    if idx != -1:
        return c[:idx + 4]
    parts = c.split()
    return parts[0] if parts else c


@dataclass(frozen=True)
class CommandCut:
    """A command line cut into the program Windows starts and the rest.

    ``exact`` is False when Windows may start a different file than
    ``program``. ``skipped`` then lists the shorter prefixes Windows tries
    first, each as ``<prefix>.exe`` (``C:\\Program Files\\x.exe -k`` is tried
    as ``C:\\Program.exe`` first); it is empty when the cut is unsure for
    another reason (an unclosed quote, no ``.exe`` to end on)."""
    program: str
    args: str
    exact: bool
    skipped: tuple[str, ...] = ()


_BLANKS = " \t"
_MAX_COMMAND = 32767        # the longest command line CreateProcess accepts


def _has_extension(path: str) -> bool:
    name = path.replace("/", "\\").rsplit("\\", 1)[-1].rstrip(". ")
    return "." in name


def split_command(cmd: str) -> CommandCut:
    """Cut a task action / service PathName / launch string the way
    ``CreateProcess`` reads a command line with no application name.

    A quoted program ends at its closing quote, whatever follows
    (``"...\\cmd.exe"/c x`` runs cmd.exe with ``/c x``). An unquoted one ends
    at the first blank: Windows tries that first word before any longer
    prefix, so ``C:\\ProgramData\\a.cmd \\..\\Windows\\System32\\sc.exe`` runs
    ``a.cmd``. Only when the first word is a path with no extension does
    Windows go on to longer prefixes; then the first prefix ending in ``.exe``
    (a stray closing quote aside) is taken, else that first word, and the cut
    is marked inexact. Never raises.
    """
    c = str(cmd or "").lstrip(_BLANKS)
    if not c:
        return CommandCut("", "", True)
    if c[0] == '"':
        end = c.find('"', 1)
        if end < 0:
            return CommandCut(c[1:], "", False)
        return CommandCut(c[1:end], c[end + 1:].strip(), True)
    blanks = [i for i, ch in enumerate(c) if ch in _BLANKS]
    if not blanks:
        return CommandCut(c, "", True)
    first = c[:blanks[0]]
    rest = c[blanks[0]:].strip()
    if not rest:
        return CommandCut(first, "", True)
    if _has_extension(first) or not any(s in first for s in "\\/"):
        return CommandCut(first, rest, True)
    if len(c) > _MAX_COMMAND:
        return CommandCut(first, rest, False)      # no real command: not worth the long search
    for n, i in enumerate(blanks[1:] + [len(c)], start=1):
        stem = c[:i].rstrip('"')
        if stem.rstrip(". ").lower().endswith(".exe"):
            skipped = tuple(c[:j] for j in blanks[:n])
            return CommandCut(stem, c[len(stem):].strip(), False, skipped)
    return CommandCut(first, rest, False)


@dataclass(frozen=True)
class ScanContext:
    """Per-scan config threaded into every collector's collect()/gather().

    Built once by the service layer at the start of a scan/baseline and passed
    down, so a collector that needs runtime config (today only ``canary``, which
    resolves its state file from ``root``) gets it WITHOUT importing ``service``
    (that would be an import cycle -- service imports the collectors). ``now`` is a
    single scan-wide timestamp (epoch seconds) so time-sensitive collectors are
    deterministic under test.
    """
    root: Path
    now: float


class Collector(ABC):
    """The collector spine: gather (impure) -> parse (pure) -> Facts.

    A subclass sets ``name`` and implements ``gather``/``parse``; ``collect`` is
    the shared template that runs the two halves. Shared detection signals live in
    this module (``is_tempish``, above) so no collector re-spells them.
    """
    name: str = ""

    @abstractmethod
    def gather(self, ctx: ScanContext) -> object:
        """Impure edge: read the OS/an external tool, return raw data."""
        ...

    @abstractmethod
    def parse(self, raw: object) -> list[Fact]:
        """Pure: raw data -> Facts. No I/O, no clock, no ctx."""
        ...

    def collect(self, ctx: ScanContext) -> list[Fact]:
        """gather(ctx) -> parse -> Facts. The one place the sequence lives."""
        return self.parse(self.gather(ctx))
