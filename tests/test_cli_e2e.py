# tests/test_cli_e2e.py
import json
from spyscan import cli, service
from spyscan.facts import Fact


def test_scan_writes_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_collect_all",
                        lambda ctx: [Fact("processes", "processes::bh::bh", "process", "bh",
                                          {"signed": False, "from_temp": True})])
    assert cli.main(["baseline"]) == 0
    rc = cli.main(["scan"])
    assert rc == 0
    assert (tmp_path / "runs" / "last_scan.json").exists()
    assert (tmp_path / "runs" / "last_scan.html").exists()


def test_scan_json_is_full_and_html_collapses_info(tmp_path, monkeypatch):
    # baseline empty -> everything is_new; one ALERT-worthy proc + many benign loopback conns
    def collect(ctx):
        facts = [Fact("processes", "processes::bh::bh", "process", "bh",
                      {"signed": False, "from_temp": True, "name": "bh"})]
        for i in range(50):
            facts.append(Fact("netconns", f"netconns::p::127.0.0.1:{1000+i}",
                              "connection", f"p -> 127.0.0.1:{1000+i}",
                              {"remote_ip": "127.0.0.1", "listening": False}))
        return facts

    monkeypatch.setattr(service, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_collect_all", collect)
    # With service.ROOT repointed at tmp, the dev indicators_dir resolves to
    # tmp/src/spyscan/rules/indicators (absent) -> empty IOC set, so "bh" is not
    # matched by the bundled procname list. This test is about info-collapse.

    assert cli.main(["baseline"]) == 0
    assert cli.main(["scan"]) == 0

    data = json.loads((tmp_path / "runs" / "last_scan.json").read_text(encoding="utf-8"))
    # JSON keeps the FULL list (1 proc + 50 conns)
    assert len(data["findings"]) == 51
    html = (tmp_path / "runs" / "last_scan.html").read_text(encoding="utf-8")
    # the 50 loopback conns are INFO (score 0) -> collapsed, not dumped as rows
    assert "127.0.0.1:1000" not in html
    assert "informational item" in html


def test_scan_returns_2_without_baseline(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_collect_all", lambda ctx: [])
    assert cli.main(["scan"]) == 2


def test_scan_defender_flag_threads_enable_defender(monkeypatch):
    # `spyscan scan --defender` -> run_scan(enable_defender=True); bare scan -> False.
    captured = {}

    def fake_run_scan(*a, **k):
        captured.clear(); captured.update(k)
        return {"findings": [],
                "summary": {"total": 0, "alert": 0, "review": 0,
                            "allowlisted": 0, "info": 0},
                "report_html_path": "x", "report_json_path": "y"}
    monkeypatch.setattr(service, "run_scan", fake_run_scan)

    assert cli.main(["scan", "--defender"]) == 0
    assert captured.get("enable_defender") is True

    assert cli.main(["scan"]) == 0
    assert captured.get("enable_defender") is False


# --- UNIT 4: allowlist surfacing in the CLI ---

def test_scan_prints_allowlisted_count(tmp_path, monkeypatch, capsys):
    # a NEW unsigned temp proc whose path is allowlisted -> floored to INFO and
    # counted in the "allowlisted: N" line.
    def collect(ctx):
        return [Fact("processes", "processes::py::py", "process", "py",
                     {"exe": r"F:\proj\.venv\Scripts\python.exe", "from_temp": True,
                      "parent": "", "name": "py"})]
    monkeypatch.setattr(service, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "_collect_all", collect)
    # write a tmp allowlist config under the patched ROOT/config (json.dumps so
    # the backslashes in the glob survive intact)
    cfg = tmp_path / "config"; cfg.mkdir()
    (cfg / "allowlist.json").write_text(
        json.dumps({"path_globs": [r"*\.venv\scripts\*"]}), encoding="utf-8")
    assert cli.main(["baseline"]) == 0
    assert cli.main(["scan"]) == 0
    out = capsys.readouterr().out.lower()
    assert "allowlisted: 1" in out


def test_allowlist_subcommand_prints_path_and_counts(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config"; cfg.mkdir()
    (cfg / "allowlist.json").write_text(
        '{"path_globs": ["a", "b"], "signers": ["x"], "sha256": [], "entity_keys": []}',
        encoding="utf-8")
    monkeypatch.setattr(service, "ROOT", tmp_path)
    rc = cli.main(["allowlist"])
    assert rc == 0
    out = capsys.readouterr().out
    assert str(cfg / "allowlist.json") in out
    assert "path_globs" in out and "2" in out  # 2 path_globs
    # ADR 0001: the built-in verified Microsoft-signed floor is surfaced too
    assert "built-in" in out and "Microsoft-signed" in out
