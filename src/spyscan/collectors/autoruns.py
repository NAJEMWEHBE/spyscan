from __future__ import annotations
import csv, io, shutil, subprocess
from pathlib import Path
from spyscan.facts import Fact, make_key
from spyscan.resources import app_base, is_frozen   # bundle_dir dropped: nothing is bundled
from spyscan.collectors.base import Collector, ScanContext, is_tempish

name = "autoruns"
ATTACK = "T1547.001"   # Boot or Logon Autostart Execution: Registry Run/Startup

# NOTE ON REDISTRIBUTION: autorunsc64.exe is NOT shipped with spyscan. The Sysinternals
# license forbids it ("you may not publish the software for others to copy" / "transfer the
# software ... to any third party"), with no free/non-commercial exception. The shipped
# build carries NO copy; default autostart coverage comes from the native
# `autostart_native` collector. This module runs autorunsc ONLY when a copy the USER
# installed (or, in dev, Nino's own private copy -- private use is permitted) is found.
#
# Dev-only location of a private user-provided autorunsc (src/spyscan/collectors -> repo).
_DEV_AUTORUNSC = Path(__file__).resolve().parents[3] / "tools" / "autorunsc64.exe"

# Standard dirs a user's own Sysinternals install may live in.
_STD_DIRS = (r"C:\Program Files\Sysinternals", r"C:\Sysinternals", r"C:\Tools\Sysinternals")


def _resolve_autorunsc() -> Path:
    """Locate a USER-PROVIDED autorunsc64.exe -- never a bundled copy.

    The Sysinternals binary is not redistributed (see the module note), so this finds a
    copy the user installed themselves; power users then still get autorunsc's full
    full `-a *` ASEP sweep, while everyone else falls back to `autostart_native`.

    Search order (first existing wins):
      a) PATH (``autorunsc64`` / ``autorunsc``),
      b) ``<exe_dir>/tools`` when frozen -- a user can drop their own next to the exe,
      c) standard Sysinternals install dirs,
      d) the dev tree (Nino's private copy; private use is permitted).
    Returns the first existing path, else a best-effort default Path named
    ``autorunsc64.exe`` so ``gather`` degrades gracefully rather than crashing.
    """
    candidates: list[Path] = []
    for exe in ("autorunsc64", "autorunsc"):
        found = shutil.which(exe)
        if found:
            candidates.append(Path(found))
    if is_frozen():
        candidates.append(app_base() / "tools" / "autorunsc64.exe")    # user-dropped next to exe
    for d in _STD_DIRS:
        candidates.append(Path(d) / "autorunsc64.exe")
    candidates.append(_DEV_AUTORUNSC)                                  # dev private copy
    for c in candidates:
        try:
            if c.exists():
                return c
        except OSError:
            continue
    # best-effort default: a Path named autorunsc64.exe (non-existent -> graceful degrade)
    return app_base() / "tools" / "autorunsc64.exe"


# Resolved once at import, for callers that just want to report where the binary would come
# from. NOT used by gather() -- see the note there; a long-lived app must not cache this.
AUTORUNSC = _resolve_autorunsc()


def autorunsc_available() -> bool:
    """True when a user-provided autorunsc is resolvable, so autoruns will run the fuller
    Sysinternals sweep. `autostart_native` reads this to step aside and avoid
    double-reporting the same autostarts."""
    try:
        return Path(_resolve_autorunsc()).exists()
    except OSError:
        return False


def gather() -> bytes:                       # impure edge (integration-tested)
    # Resolve FRESH on every scan -- never from the import-time AUTORUNSC constant.
    # The packaged app is a long-lived process that scans in-process, so a user can install
    # autorunsc between launch and scan. `autorunsc_available()` already re-resolves, and
    # `autostart_native` steps aside the moment it returns True; if THIS function still
    # pointed at the stale import-time path it would raise while native had already bowed
    # out, and the scan would silently produce NO autostart facts at all (the warning is a
    # print, invisible in the windowed console=False build). Resolving here keeps the two
    # in agreement whichever of the documented install locations the user chose.
    exe = _resolve_autorunsc()
    # Degrade gracefully when the binary is absent (the shipped default -- nothing is
    # bundled): raise so collect_all logs a warning and the scan continues with the other
    # collectors instead of crashing.
    if not Path(exe).exists():
        raise FileNotFoundError(f"autorunsc not found at {exe}")
    out = subprocess.run(
        [str(exe), "-accepteula", "-a", "*", "-c", "-h", "-s", "-nobanner"],
        capture_output=True, timeout=180)
    return out.stdout

def _decode(raw: bytes) -> str:
    """Real autorunsc -c emits UTF-16-LE with a BOM; tolerate UTF-8 too."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    # Heuristic: lots of NUL bytes -> UTF-16 without (or with stripped) BOM
    if b"\x00" in raw[:64]:
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")

def _split_verified(signer_field: str) -> tuple[bool | None, str]:
    """Real autorunsc folds verification into the Signer column:
    '(Verified) Microsoft Windows' or '(Not verified) ...' or ''.
    Some builds DOUBLE the prefix, e.g.
    '(Not verified) (Not Verified) Microsoft Corporation'.
    The FIRST prefix decides verified; ALL leading prefixes are stripped so the
    returned signer is fully clean.
    An EMPTY field is unknown, not unsigned: None, never False, so score.py's
    `verified is False` penalty cannot fire for a row autorunsc simply did not
    sign-check (ADR 0002 rule 4 -- same determinate-vs-unknown line the pipeline
    enrichment pass already draws).
    Returns (verified_bool_or_None, clean_signer_without_prefix)."""
    s = (signer_field or "").strip()
    if not s:
        return None, ""
    verified = s.lower().startswith("(verified)")  # first prefix decides
    # loop-strip every leading (Verified)/(Not verified) prefix (case-insensitive)
    while True:
        low = s.lower()
        for prefix in ("(verified)", "(not verified)"):
            if low.startswith(prefix):
                s = s[len(prefix):].strip()
                break
        else:
            break
    return verified, s

def parse(raw: bytes) -> list[Fact]:         # PURE
    text = _decode(raw)
    reader = csv.DictReader(io.StringIO(text))
    facts: list[Fact] = []
    for row in reader:
        loc = (row.get("Entry Location") or "").strip()
        entry = (row.get("Entry") or "").strip()
        if not entry and not loc:
            continue
        image_path = (row.get("Image Path") or "").strip()
        launch_string = (row.get("Launch String") or "").strip()
        # autorunsc -a * emits one HEADER row per ASEP location (Entry, Image
        # Path, Launch String all empty -- only the location + category filled).
        # A header is a container, not an autostart (ADR 0002 rule 2): skip it,
        # or it becomes a junk fact with a false unsigned penalty.
        if not entry and not image_path and not launch_string:
            continue
        # Real builds fold verification into Signer; a separate "Verified"
        # column (plan's guess) is honored too if a future build emits one.
        verified, signer_clean = _split_verified(row.get("Signer", ""))
        if "Verified" in row and (row.get("Verified") or "").strip():
            verified = "(verified)" in (row.get("Verified") or "").strip().lower()
        facts.append(Fact(
            collector=name,
            # Identity needs image_path AND launch_string: genuine duplicate
            # autostarts share location+entry but differ by binary (image), and
            # distinct real records (Active Setup GUIDs with one display name;
            # multi-action tasks) share the image and differ only by launch.
            # Keying without either silently drops/masks them.
            entity_key=make_key(name, loc, entry, image_path, launch_string),
            kind="autostart",
            label=f"{entry} ({image_path})",
            attack_id=ATTACK,
            attrs={
                "entry": entry,
                "location": loc,
                "image_path": image_path,
                "launch_string": launch_string,
                "company": (row.get("Company") or "").strip(),
                "signer": signer_clean,
                "verified": verified,
                "sha256": (row.get("SHA-256") or row.get("SHA256") or "").strip(),
                "md5": (row.get("MD5") or "").strip(),
                "enabled": (row.get("Enabled") or "").strip().lower() == "enabled",
                # temp-resident autostart = classic persistence; check the image
                # path AND the launch string (autorunsc -c often leaves Image Path
                # blank while the real path sits in the launch command).
                "from_temp": is_tempish(image_path) or is_tempish(launch_string),
            },
        ))
    # autorunsc emits some records once PER registering GUID (GpExtensions) with
    # the GUID absent from the CSV -- byte-identical rows for one real entity.
    # Fold exact duplicates (ADR 0002 rule 2); a collision with DIFFERING attrs
    # would be a real defect and is deliberately left visible to the key-unique
    # invariant checks rather than papered over here.
    uniq, seen = [], set()
    for f in facts:
        fp = (f.entity_key, tuple(sorted(f.attrs.items())))
        if fp not in seen:
            seen.add(fp)
            uniq.append(f)
    return uniq


class AutorunsCollector(Collector):
    """Autostart entries (Sysinternals autorunsc). No config -> ignores ctx."""
    name = "autoruns"

    def gather(self, ctx: ScanContext) -> bytes:
        return gather()

    def parse(self, raw) -> list[Fact]:
        return parse(raw)
