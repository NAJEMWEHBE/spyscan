# src/spyscan/canary.py
"""Local canary-token / honeyfile tripwire (the behavioral layer).

This is the "catch the unknown implant by its behavior" layer. We plant decoy
files with tempting names + believable-but-fake bait content in tempting (but
safe) locations. If anything later READS, COPIES, or MODIFIES one of them, that
is a strong spying signal -- a benign user has no reason to open a file called
``crypto_wallet_seed.txt`` they never created.

LOCAL-ONLY by design. There is NO network callback, NO web beacon, NO
canarytokens.org-style remote token. Detection is 100% on-box: we record each
decoy's hash/size/mtime/atime at deploy time and compare on demand. That keeps
the tool true to its core principle -- nothing ever leaves the machine.

Detection signals (strongest first):
  * sha256 changed   -- file content was modified (definitive tamper).
  * size changed     -- content changed even if a collision were attempted.
  * mtime advanced   -- file was written after we planted it.
  * missing          -- decoy deleted/moved/renamed (exfil-then-cleanup).
  * atime advanced   -- file was *read* (weak on Windows; see ATIME_NOTE).

All I/O is parameterised (targets, state_path, now) so the module is unit
-testable without touching real user directories or the wall clock.
"""
from __future__ import annotations
import hashlib
import json
import os
import random
from pathlib import Path

from spyscan.resources import app_base

# Last-access time (atime) is the only signal that catches a pure READ with no
# write. But on most Windows installs NTFS "last access" updates are DISABLED by
# default (fsutil behavior query disablelastaccess -> usually 1/3), so atime
# often does NOT move even when a file is read. We therefore treat atime as a
# best-effort hint only, behind a tolerance, and rely mainly on hash/mtime/size/
# missing -- which catch any modify/copy-with-touch/delete and are reliable.
ATIME_NOTE = ("atime (last-access) is unreliable on Windows: NTFS last-access "
              "updates may be disabled or system-managed depending on config; "
              "rely on hash/mtime/size/missing")
_ATIME_TOLERANCE_S = 2.0

# Decoy bait: generic and RANDOM per deploy (audit #15). Fixed names and bytes
# would let an implant recognise spyscan's decoys and skip them, and bait in a
# public repo must hold no personal-looking data, so every value below is
# generated: no real names, domains only under the reserved .example TLD
# (RFC 2606), account numbers in no real bank format.
_NAME_POOLS = {
    "credentials": ("passwords.txt", "logins.txt", "my_passwords.txt",
                    "accounts.txt", "passwords_backup.txt"),
    "seed": ("crypto_wallet_seed.txt", "wallet_recovery.txt", "seed_phrase.txt",
             "wallet_backup.txt"),
    "payroll": ("payroll.csv", "salaries.csv", "staff_salaries.csv", "payroll_export.csv"),
    "vpn": ("vpn_credentials.txt", "vpn_login.txt", "remote_access.txt", "vpn_config.txt"),
}
_KIND_HINTS = (("seed", "seed"), ("wallet", "seed"), ("recovery", "seed"),
               ("payroll", "payroll"), ("salar", "payroll"),
               ("vpn", "vpn"), ("remote", "vpn"),
               ("pass", "credentials"), ("login", "credentials"), ("account", "credentials"))
_WORDS = ("ridge", "napkin", "oyster", "cabin", "velvet", "pioneer", "tonic", "ladder",
          "gospel", "quantum", "meadow", "shrimp", "harbor", "pencil", "orbit", "lemon",
          "canvas", "timber", "falcon", "marble", "violet", "summit", "rocket", "pepper")
_SURNAMES = ("Smith", "Garcia", "Chen", "Khan", "Silva", "Novak", "Haddad", "Okafor",
             "Larsen", "Moreau", "Rossi", "Tanaka")
_ROLES = ("Manager", "Editor", "Designer", "Accountant", "Engineer", "Coordinator")


def _rand_pass(rng: random.Random) -> str:
    return (rng.choice(_WORDS).capitalize() + rng.choice("!#@$%&")
            + rng.choice(_WORDS) + str(rng.randint(10, 99)))


def _rand_user(rng: random.Random) -> str:
    return rng.choice(_WORDS) + str(rng.randint(100, 999))


def _bait_for(kind: str, rng: random.Random) -> str:
    """Believable-but-fake, randomised content for one decoy kind."""
    if kind == "credentials":
        return ("# logins (do not share)\n"
                f"email     {_rand_user(rng)}@mail.example / {_rand_pass(rng)}\n"
                f"bank      {_rand_user(rng)} / {_rand_pass(rng)}\n"
                f"router    admin / {_rand_pass(rng)}\n")
    if kind == "seed":
        words = [rng.choice(_WORDS) for _ in range(12)]
        return ("recovery phrase - KEEP OFFLINE\n"
                + " ".join(words[:6]) + "\n" + " ".join(words[6:]) + "\n")
    if kind == "payroll":
        rows = [f"{rng.choice('ABCDEFGHJKLMNPRSTW')}. {rng.choice(_SURNAMES)},"
                f"{rng.choice(_ROLES)},{rng.randint(900, 4200)},"
                f"ACCT-{rng.randint(10**7, 10**8 - 1)}" for _ in range(rng.randint(2, 4))]
        return "Employee,Role,Monthly,Account\n" + "\n".join(rows) + "\n"
    if kind == "vpn":
        return ("[vpn]\n"
                f"server = vpn.{rng.choice(_WORDS)}.example:{rng.choice((443, 1194, 51820))}\n"
                f"user   = {_rand_user(rng)}\n"
                f"pass   = {_rand_pass(rng)}\n"
                f"psk    = {rng.getrandbits(64):016x}\n")
    return f"confidential - internal use only\nref {rng.getrandbits(48):012x}\n"


def _kind_of(name: str) -> str:
    low = name.lower()
    return next((kind for hint, kind in _KIND_HINTS if hint in low), "generic")


def default_names(rng: random.Random) -> list[str]:
    """One randomly-picked tempting name per bait kind."""
    return [rng.choice(pool) for pool in _NAME_POOLS.values()]


def default_state_path(base: Path | None = None) -> Path:
    """Canonical state file: ``<base>/config/canary_state.json``.

    ``base`` defaults to ``app_base()`` (the writable runtime base: repo root in
    dev, the dir next to the exe when frozen). Passing an explicit ``base`` lets
    the ``service`` layer resolve this same join against a test-repointed
    ``root`` -- WITHOUT canary importing ``service`` (that would be a cycle:
    service imports the collectors, and the canary collector imports this module).
    So this stays the ONE place the ``config/canary_state.json`` join is spelled.
    """
    return (base if base is not None else app_base()) / "config" / "canary_state.json"


def _default_targets() -> list[Path]:
    """Default plant locations: the user's Desktop + Documents + an app-local
    ``canaries/`` dir. Tempting-but-safe; we never overwrite real files there."""
    home = Path.home()
    return [home / "Desktop", home / "Documents", app_base() / "canaries"]


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _record(p: Path, planted_at: float) -> dict:
    """Fingerprint a freshly-planted decoy.

    Order matters: we hash FIRST (reading the file can bump atime on filesystems
    where last-access updates are enabled), THEN pin mtime+atime back to
    ``planted_at`` via os.utime, THEN stat. That way the recorded atime/mtime
    match what's on disk afterwards, so an untouched canary does not self-trip
    on the deploy-time read.
    """
    sha = _sha256(p)
    os.utime(p, (planted_at, planted_at))
    st = p.stat()
    return {
        "path": str(p),
        "planted_at": planted_at,
        "size": st.st_size,
        "sha256": sha,
        "mtime": st.st_mtime,
        "atime": st.st_atime,
    }


def deploy(targets: list[Path] | None = None, state_path: Path | None = None,
           now: float = 0.0, names: list[str] | None = None,
           rng: random.Random | None = None) -> dict:
    """Plant decoy files and record their fingerprints to ``state_path``.

    Args:
      targets:    dirs to plant into (default: Desktop + Documents + canaries/).
                  Each dir is created if missing.
      state_path: where to write the JSON state (default: default_state_path()).
      now:        timestamp to stamp as ``planted_at`` (injected -- no clock read).
      names:      decoy filenames to use (default: one random tempting name per
                  bait kind); each gets random bait fitting its name.
      rng:        randomness source (default: the OS CSPRNG); tests seed it.

    Never overwrites an existing real file: if a chosen name already exists in a
    target dir, that name is SKIPPED for that dir (and not recorded), so a user's
    own file can never be clobbered or mistaken for a canary.

    A second deploy ADDS to the existing state (audit #8): decoys planted earlier
    stay tracked, so check() still watches them and clear() still removes them.

    Returns a summary dict: {planted, state_path, canaries:[paths...], skipped}.
    """
    targets = [Path(t) for t in (targets if targets is not None else _default_targets())]
    state_path = Path(state_path) if state_path is not None else default_state_path()
    rng = rng if rng is not None else random.SystemRandom()
    names = list(names) if names is not None else default_names(rng)
    previous = (_load_state(state_path) or {}).get("canaries") or []
    tracked = {str(r.get("path", "")).lower() for r in previous}

    records: list[dict] = []
    skipped: list[str] = []
    for tdir in targets:
        try:
            tdir.mkdir(parents=True, exist_ok=True)
        except Exception:
            skipped.append(str(tdir) + " (mkdir failed)")
            continue
        for nm in names:
            dest = tdir / nm
            if dest.exists():
                # never clobber a real file the user already has (or re-plant
                # one of our own decoys: it stays tracked from the earlier deploy)
                skipped.append(str(dest) + (" (already a decoy)"
                                            if str(dest).lower() in tracked else ""))
                continue
            body = _bait_for(_kind_of(nm), rng)
            try:
                dest.write_text(body, encoding="utf-8")
                # _record hashes then pins mtime/atime to `now`, giving check()
                # a stable baseline independent of filesystem-clock skew.
                records.append(_record(dest, now))
            except Exception:
                skipped.append(str(dest) + " (write failed)")

    state = {"canaries": list(previous) + records, "deployed_at": now,
             "atime_note": ATIME_NOTE}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    return {"planted": len(records),
            "state_path": str(state_path),
            "canaries": [r["path"] for r in records],
            "skipped": skipped}


def _load_state(state_path: Path) -> dict | None:
    try:
        data = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def check(state_path: Path | None = None, now: float = 0.0) -> list[dict]:
    """Compare each recorded canary's CURRENT fingerprint vs what was planted.

    Returns one record per canary:
      {path, tripped: bool, reasons: [...], evidence: {...}}

    tripped is True if the file is missing OR its sha256/size/mtime changed, OR
    its atime advanced beyond a small tolerance (the atime branch is flagged as
    unreliable on Windows -- see ATIME_NOTE). An absent/unreadable state file
    yields an empty list (nothing deployed == nothing to check, zero noise).
    """
    state_path = Path(state_path) if state_path is not None else default_state_path()
    data = _load_state(state_path)
    if not data or not data.get("canaries"):
        return []

    out: list[dict] = []
    for rec in data["canaries"]:
        p = Path(rec["path"])
        reasons: list[str] = []
        evidence: dict = {"path": rec["path"]}

        if not p.exists():
            out.append({"path": rec["path"], "tripped": True,
                        "reasons": ["canary missing (deleted/moved/renamed)"],
                        "evidence": {"path": rec["path"], "expected_sha256": rec["sha256"]}})
            continue

        try:
            st = p.stat()
            cur_sha = _sha256(p)
            # Pin atime back to the pre-hash value: OUR read must not become next
            # scan's "possible read" evidence (self-churn; ADR 0002 rule 3). A
            # genuine snoop's advance is already captured in ``st`` above.
            try:
                os.utime(p, (st.st_atime, st.st_mtime))
            except OSError:
                pass  # best-effort: a locked file just keeps the weak-hint noise
        except Exception as e:
            # unreadable now but was readable at deploy -> treat as a trip
            out.append({"path": rec["path"], "tripped": True,
                        "reasons": [f"canary unreadable now ({e.__class__.__name__})"],
                        "evidence": {"path": rec["path"]}})
            continue

        # RELIABLE signals -- any of these flips tripped=True.
        if cur_sha != rec["sha256"]:
            reasons.append("content hash changed (file modified)")
            evidence["sha256"] = {"was": rec["sha256"], "now": cur_sha}
        if st.st_size != rec["size"]:
            reasons.append("size changed")
            evidence["size"] = {"was": rec["size"], "now": st.st_size}
        if st.st_mtime > rec["mtime"] + 1e-6:
            reasons.append("mtime advanced (file written after planting)")
            evidence["mtime"] = {"was": rec["mtime"], "now": st.st_mtime}
        tripped = bool(reasons)

        # atime is a WEAK hint only: it is noted but never trips on its own,
        # because (a) Windows usually disables last-access updates so a real read
        # leaves it untouched, and (b) check() itself reads the file to hash it,
        # which would otherwise self-trip every re-scan. See ATIME_NOTE.
        if st.st_atime > rec["atime"] + _ATIME_TOLERANCE_S:
            reasons.append("atime advanced (possible read; weak/unreliable - "
                           + ATIME_NOTE + ")")
            evidence["atime"] = {"was": rec["atime"], "now": st.st_atime}

        out.append({"path": rec["path"], "tripped": tripped,
                    "reasons": reasons or ["unchanged"], "evidence": evidence})
    return out


def clear(state_path: Path | None = None) -> dict:
    """Remove every planted canary file + the state file itself.

    Safe to call when nothing was deployed (missing/unreadable state -> no-op).
    Returns {removed:[paths...], missing:[paths...]} for reporting.
    """
    state_path = Path(state_path) if state_path is not None else default_state_path()
    data = _load_state(state_path)
    removed: list[str] = []
    missing: list[str] = []
    if data and data.get("canaries"):
        for rec in data["canaries"]:
            p = Path(rec["path"])
            try:
                if p.exists():
                    p.unlink()
                    removed.append(str(p))
                else:
                    missing.append(str(p))
            except Exception:
                missing.append(str(p) + " (unlink failed)")
    try:
        Path(state_path).unlink()
    except Exception:
        pass
    return {"removed": removed, "missing": missing}
