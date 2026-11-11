# tests/test_allowlist.py
import json
from spyscan.allowlist import REFUSED_OUTSIDE, REFUSED_UNNAMED, Allowlist, microsoft_floor


def _write(tmp_path, data):
    p = tmp_path / "al.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# --- load ---

def test_load_missing_file_is_empty(tmp_path):
    al = Allowlist.load(tmp_path / "nope.json")
    matched, reason = al.matches({"exe": r"C:\Windows\Temp\x.exe"})
    assert matched is False and reason == ""


def test_load_reads_rules(tmp_path):
    p = _write(tmp_path, {"signers": ["Acme Corp"], "path_globs": [r"*\.venv\scripts\*"],
                          "sha256": ["abc"], "entity_keys": ["processes::k::k"]})
    al = Allowlist.load(p)
    assert al.signers and al.path_globs and al.sha256 and al.entity_keys


# --- path_globs (fnmatch over exe/image_path, lowercased) ---

def test_path_glob_matches_exe(tmp_path):
    p = _write(tmp_path, {"path_globs": [r"*\.venv\scripts\*"]})
    al = Allowlist.load(p)
    matched, reason = al.matches({"exe": r"F:\proj\.venv\Scripts\python.exe"})
    assert matched is True
    assert "allowlisted:" in reason and "python.exe" in reason.lower()


def test_path_glob_matches_image_path(tmp_path):
    p = _write(tmp_path, {"path_globs": [r"c:\python314\*"]})
    al = Allowlist.load(p)
    matched, reason = al.matches({"image_path": r"C:\Python314\python.exe"})
    assert matched is True


def test_path_glob_case_insensitive(tmp_path):
    p = _write(tmp_path, {"path_globs": [r"*\UV\PYTHON\*"]})
    al = Allowlist.load(p)
    matched, _ = al.matches({"exe": r"C:\Users\n\AppData\Roaming\uv\python\x\python.exe"})
    assert matched is True


def test_path_glob_no_match(tmp_path):
    p = _write(tmp_path, {"path_globs": [r"*\.venv\scripts\*"]})
    al = Allowlist.load(p)
    matched, reason = al.matches({"exe": r"C:\Windows\Temp\evil.exe"})
    assert matched is False and reason == ""


# --- signers (substring, case-insensitive) ---

def test_signer_substring_match(tmp_path):
    p = _write(tmp_path, {"signers": ["acme corp"]})
    al = Allowlist.load(p)
    matched, reason = al.matches({"signer": "ACME Corp, O=Acme, C=US"})
    assert matched is True and "acme" in reason.lower()


def test_signer_no_match(tmp_path):
    p = _write(tmp_path, {"signers": ["acme corp"]})
    al = Allowlist.load(p)
    matched, _ = al.matches({"signer": "Evil Co"})
    assert matched is False


# --- sha256 / md5 hash set ---

def test_sha256_match(tmp_path):
    p = _write(tmp_path, {"sha256": ["DEADBEEF"]})
    al = Allowlist.load(p)
    matched, reason = al.matches({"sha256": "deadbeef"})
    assert matched is True and "deadbeef" in reason.lower()


def test_md5_match_against_hash_set(tmp_path):
    p = _write(tmp_path, {"sha256": ["aabbcc"]})
    al = Allowlist.load(p)
    matched, _ = al.matches({"md5": "AABBCC"})
    assert matched is True


# --- entity_keys (exact) ---

def test_entity_key_match(tmp_path):
    p = _write(tmp_path, {"entity_keys": ["processes::p::p"]})
    al = Allowlist.load(p)
    matched, reason = al.matches({"entity_key": "processes::p::p"})
    assert matched is True and "processes::p::p" in reason


def test_empty_allowlist_matches_nothing(tmp_path):
    p = _write(tmp_path, {})
    al = Allowlist.load(p)
    matched, reason = al.matches({"exe": r"C:\x.exe", "signer": "Whatever",
                                  "sha256": "ff", "entity_key": "k"})
    assert matched is False and reason == ""


# --- built-in Microsoft-signed floor (ADR 0001; folded from score.py) ---

def test_builtin_trusted_ms_matches_even_empty_allowlist(tmp_path):
    al = Allowlist.load(tmp_path / "nope.json")  # empty user allowlist
    matched, reason = al.matches({"trusted_ms": True, "exe": r"C:\Windows\System32\svchost.exe"})
    assert matched is True and "microsoft-signed" in reason.lower()


def test_builtin_verified_microsoft_signer_matches():
    matched, reason = Allowlist().matches({"verified": True, "signer": "Microsoft Windows",
                                           "image_path": r"C:\Windows\System32\svchost.exe"})
    assert matched is True and "microsoft-signed" in reason.lower()


def test_builtin_floor_needs_a_named_program():
    # a verified Microsoft signer on an entry that names no program: there is
    # nothing for the signature to stand for
    attrs = {"verified": True, "signer": "Microsoft Windows"}
    assert microsoft_floor(attrs) == (False, REFUSED_UNNAMED)
    assert Allowlist().matches(attrs)[0] is False


def test_autoruns_row_with_a_blank_image_path_is_judged_by_its_launch_string():
    # Autoruns can leave Image Path blank and still give a Launch String: the
    # program is cut out of it, and the location rule applies to that program
    ms = {"verified": True, "signer": "Microsoft Windows", "image_path": ""}
    outside = {**ms, "launch_string": r"C:\Users\v\Documents\updater.exe /background"}
    assert microsoft_floor(outside) == (False, REFUSED_OUTSIDE)
    inside = {**ms, "launch_string": r"C:\Windows\System32\SecurityHealthSystray.exe"}
    assert microsoft_floor(inside) == (True, "")


def test_builtin_unverified_microsoft_signer_does_not_match():
    # regression guard: a spoofed/invalid signature claiming Microsoft must NOT floor
    matched, reason = Allowlist().matches({"verified": False, "signer": "Microsoft Windows"})
    assert matched is False and reason == ""


def test_builtin_ms_rule_is_enumerable():
    assert any("microsoft" in r.lower() for r in Allowlist().builtin_rules())
