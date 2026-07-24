from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from spyscan.facts import Fact

# Temp-ish path fragments: an image/exe/launch path containing one of these runs
# from a user-writable, low-trust location (%TEMP%, AppData) -- a strong "not a
# normally-installed program" signal. SINGLE SOURCE OF TRUTH: every collector
# derives its ``from_temp`` attr from is_tempish(), so the heuristic is spelled once.
_TEMPISH = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\appdata\\roaming\\")


def is_tempish(path: str) -> bool:
    """True if ``path`` sits under a temp/AppData location (case-insensitive)."""
    low = (path or "").lower()
    return any(t in low for t in _TEMPISH)


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
