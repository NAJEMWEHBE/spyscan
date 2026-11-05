"""Audit #8 + #15: canary state survives a second deploy; bait is generic + random.

#8: a second deploy skipped the existing decoys (they collide by name) and then
    overwrote the state with an empty list, so check() saw nothing and clear()
    left every decoy on the user's Desktop.
#15: the bait text held personal-looking data (a real name, a work username, an
    internal domain, an IBAN-like string) and every install planted the same
    names and bytes, so an implant could recognise spyscan's decoys and skip them.
"""
from __future__ import annotations
import json
import random
import re
from pathlib import Path

from spyscan import canary

T0 = 1_700_000_000.0
_PERSONAL = re.compile(r"najm|wehbe|hdmedia|hdmb|kwbank|nwehbe|KW\d\d", re.IGNORECASE)


def _decoys(d: Path) -> list[Path]:
    return sorted(p for p in d.iterdir() if p.is_file())


def test_second_deploy_keeps_tracking_the_first_decoys(tmp_path):
    d, st = tmp_path / "d", tmp_path / "state.json"
    first = canary.deploy(targets=[d], state_path=st, now=T0)
    canary.deploy(targets=[d], state_path=st, now=T0 + 10)
    tracked = {r["path"] for r in json.loads(st.read_text(encoding="utf-8"))["canaries"]}
    assert set(first["canaries"]) <= tracked
    assert len(canary.check(st, now=T0 + 20)) == len(tracked) == len(_decoys(d))


def test_clear_after_two_deploys_removes_every_decoy(tmp_path):
    d, st = tmp_path / "d", tmp_path / "state.json"
    canary.deploy(targets=[d], state_path=st, now=T0, rng=random.Random(1))
    canary.deploy(targets=[d], state_path=st, now=T0 + 10, rng=random.Random(2))
    canary.clear(st)
    assert _decoys(d) == []


def test_untouched_first_decoys_do_not_trip_after_a_redeploy(tmp_path):
    d, st = tmp_path / "d", tmp_path / "state.json"
    canary.deploy(targets=[d], state_path=st, now=T0)
    canary.deploy(targets=[d], state_path=st, now=T0 + 10)
    assert not [t for t in canary.check(st, now=T0 + 20) if t["tripped"]]


def test_bait_holds_no_personal_looking_data(tmp_path):
    for seed in range(20):
        d = tmp_path / f"d{seed}"
        canary.deploy(targets=[d], state_path=tmp_path / f"s{seed}.json", now=T0,
                      rng=random.Random(seed))
        for p in _decoys(d):
            assert not _PERSONAL.search(p.name + p.read_text(encoding="utf-8")), p


def test_canary_source_holds_no_personal_bait():
    src = Path(canary.__file__).read_text(encoding="utf-8")
    assert not _PERSONAL.search(src)


def test_names_and_content_differ_between_installs(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    canary.deploy(targets=[a], state_path=tmp_path / "sa.json", now=T0, rng=random.Random(1))
    canary.deploy(targets=[b], state_path=tmp_path / "sb.json", now=T0, rng=random.Random(2))
    names_a = [p.name for p in _decoys(a)]
    names_b = [p.name for p in _decoys(b)]
    bodies_a = {p.read_text(encoding="utf-8") for p in _decoys(a)}
    bodies_b = {p.read_text(encoding="utf-8") for p in _decoys(b)}
    assert names_a != names_b
    assert not bodies_a & bodies_b


def test_one_decoy_of_each_kind_by_default(tmp_path):
    d = tmp_path / "d"
    res = canary.deploy(targets=[d], state_path=tmp_path / "s.json", now=T0,
                        rng=random.Random(3))
    assert res["planted"] == 4


def test_explicit_names_still_get_a_fitting_random_body(tmp_path):
    d = tmp_path / "d"
    canary.deploy(targets=[d], state_path=tmp_path / "s.json", now=T0,
                  names=["passwords.txt"], rng=random.Random(4))
    body = (d / "passwords.txt").read_text(encoding="utf-8")
    assert body.strip() and not _PERSONAL.search(body)
