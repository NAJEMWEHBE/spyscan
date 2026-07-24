# tests/test_cli_canary.py
"""UNIT 4 - `spyscan canary deploy|status|clear` CLI subcommands.

The CLI asks spyscan.service for the canary state path (service.canary_state_path
-> <root>/config/canary_state.json), so tests monkeypatch service.ROOT to
tmp_path and exercise the real deploy/check/clear against an isolated directory
(no real Desktop/Documents touched).
"""
import json
from pathlib import Path

from spyscan import cli, service


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "ROOT", tmp_path)


def test_canary_deploy_plants_and_prints(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    # plant into a tmp targets dir so nothing real is touched
    rc = cli.main(["canary", "deploy", "--into", str(tmp_path / "decoys")])
    assert rc == 0
    out = capsys.readouterr().out.lower()
    assert "planted" in out
    # state file written under ROOT/config
    state = tmp_path / "config" / "canary_state.json"
    assert state.exists()
    data = json.loads(state.read_text(encoding="utf-8"))
    assert data["canaries"]
    # the decoy files exist
    for r in data["canaries"]:
        assert Path(r["path"]).exists()


def test_canary_status_lists_and_flags_trip(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    cli.main(["canary", "deploy", "--into", str(tmp_path / "d")])
    capsys.readouterr()  # drain
    # untouched -> status shows OK / no trips
    assert cli.main(["canary", "status"]) == 0
    out = capsys.readouterr().out.lower()
    assert "canar" in out
    assert "tripped" not in out or "0" in out

    # now trip one and re-check status -> reports a trip
    state = tmp_path / "config" / "canary_state.json"
    data = json.loads(state.read_text(encoding="utf-8"))
    victim = Path(data["canaries"][0]["path"])
    victim.write_text("SNOOPED", encoding="utf-8")
    import os
    os.utime(victim, (data["deployed_at"] + 999, data["deployed_at"] + 999))
    rc = cli.main(["canary", "status"])
    out = capsys.readouterr().out.lower()
    assert rc != 0  # non-zero exit signals a trip (like scan's ALERT)
    assert "tripped" in out


def test_canary_clear_removes_files(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    cli.main(["canary", "deploy", "--into", str(tmp_path / "d")])
    state = tmp_path / "config" / "canary_state.json"
    data = json.loads(state.read_text(encoding="utf-8"))
    planted = [Path(r["path"]) for r in data["canaries"]]
    capsys.readouterr()
    rc = cli.main(["canary", "clear"])
    assert rc == 0
    out = capsys.readouterr().out.lower()
    assert "remov" in out or "clear" in out
    for p in planted:
        assert not p.exists()
    assert not state.exists()


def test_canary_status_without_deploy_is_clean(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    rc = cli.main(["canary", "status"])
    out = capsys.readouterr().out.lower()
    assert rc == 0  # nothing deployed -> clean, zero exit
    assert "no canar" in out or "0" in out
