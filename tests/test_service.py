# tests/test_service.py
import json
from spyscan import service
from spyscan.facts import Fact


def _empty_ind(tmp_path):
    d = tmp_path / "ind"
    d.mkdir()
    return d


def test_run_baseline_returns_count(tmp_path):
    facts = [Fact("processes", "processes::a::a", "process", "a", {}),
             Fact("processes", "processes::b::b", "process", "b", {})]
    n = service.run_baseline(tmp_path, tmp_path / "b.db", collect=lambda ctx: facts)
    assert n == 2


def test_run_scan_returns_dict_with_summary_and_writes_files(tmp_path):
    # one ALERT-worthy unsigned temp proc + 30 benign loopback conns (INFO)
    def collect(ctx):
        facts = [Fact("processes", "processes::bh::bh", "process", "bh",
                      {"signed": False, "from_temp": True, "name": "bh"})]
        for i in range(30):
            facts.append(Fact("netconns", f"netconns::p::127.0.0.1:{1000+i}",
                              "connection", f"p -> 127.0.0.1:{1000+i}",
                              {"remote_ip": "127.0.0.1", "listening": False}))
        return facts

    db = tmp_path / "b.db"
    # seed a throwaway baseline fact (an empty baseline is indistinguishable
    # from 'no baseline'); the scan facts below are all is_new vs this seed
    service.run_baseline(tmp_path, db, collect=lambda ctx: [
        Fact("processes", "processes::seed::seed", "process", "seed", {})])
    result = service.run_scan(tmp_path, db, collect=collect,
                              ind=_empty_ind(tmp_path))

    # shape
    assert set(result) == {"meta", "summary", "findings",
                           "report_html_path", "report_json_path"}
    assert set(result["meta"]) == {"host", "when"}
    s = result["summary"]
    assert set(s) == {"alert", "review", "info", "allowlisted", "total"}

    # counts: 31 total facts; the temp-unsigned proc is ALERT/REVIEW, the 30
    # loopback conns are INFO (score 0)
    assert s["total"] == 31
    assert s["info"] == 30
    assert s["alert"] + s["review"] >= 1
    assert s["total"] == s["alert"] + s["review"] + s["info"]
    assert len(result["findings"]) == 31  # full list, every bucket

    # both report files written and parseable
    assert (tmp_path / "runs" / "last_scan.html").exists()
    jpath = tmp_path / "runs" / "last_scan.json"
    assert jpath.exists()
    data = json.loads(jpath.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 31
    assert result["report_html_path"].endswith("last_scan.html")
    assert result["report_json_path"].endswith("last_scan.json")


def test_run_scan_without_baseline_raises(tmp_path):
    import pytest
    with pytest.raises(RuntimeError):
        service.run_scan(tmp_path, tmp_path / "none.db", collect=lambda ctx: [],
                         ind=_empty_ind(tmp_path))


def test_canary_state_path_delegates_to_canary_join(tmp_path):
    from spyscan import canary
    # resolves against an explicit root ...
    assert service.canary_state_path(tmp_path) == tmp_path / "config" / "canary_state.json"
    # ... by delegating to the ONE join that lives in canary (no second copy)
    assert service.canary_state_path(tmp_path) == canary.default_state_path(tmp_path)


def test_service_root_is_the_single_seam(tmp_path, monkeypatch):
    # monkeypatching service.ROOT repoints EVERY resolver with no explicit args,
    # because each reads ROOT at call time via _root().
    monkeypatch.setattr(service, "ROOT", tmp_path)
    assert service.runs_dir() == tmp_path / "runs"
    assert service.allowlist_path() == tmp_path / "config" / "allowlist.json"
    assert service.canary_state_path() == tmp_path / "config" / "canary_state.json"
    assert service.indicators_dir() == tmp_path / "src" / "spyscan" / "rules" / "indicators"


def test_db_derives_from_resolved_root(tmp_path, monkeypatch):
    # no explicit db -> baseline.db lands under the resolved root (single seam),
    # so a run_baseline with only the collector writes <root>/baseline.db.
    monkeypatch.setattr(service, "ROOT", tmp_path)
    n = service.run_baseline(collect=lambda ctx: [
        Fact("processes", "processes::a::a", "process", "a", {})])
    assert n == 1
    assert (tmp_path / "baseline.db").exists()


def test_run_scan_enable_defender_threads_scanner(tmp_path, monkeypatch):
    # enable_defender=True invokes defender.scan_file on a suspicious candidate and
    # surfaces defender_hit; the default (off) never calls it.
    from spyscan.enrich import defender as _defender
    from spyscan.enrich import signature as _sig
    # keep the real signer from shelling out to PowerShell for the candidate's path
    monkeypatch.setattr(_sig, "authenticode",
                        lambda p: {"signed": None, "verified": None,
                                   "trusted_ms": False, "signer": ""})
    seen = {"n": 0}

    def fake_scan(path):
        seen["n"] += 1
        return {"defender_hit": True, "threat": "Trojan:Win32/Test"}
    monkeypatch.setattr(_defender, "scan_file", fake_scan)

    def collect(ctx):
        return [Fact("processes", "processes::imp::imp", "process", "imp",
                     {"exe": r"C:\Windows\Temp\imp.exe", "from_temp": True,
                      "parent": "", "name": "imp"})]
    db = tmp_path / "b.db"
    empty = _empty_ind(tmp_path)
    service.run_baseline(tmp_path, db, collect=lambda ctx: [
        Fact("processes", "processes::seed::seed", "process", "seed", {})])
    result = service.run_scan(tmp_path, db, collect=collect, ind=empty,
                              enable_defender=True)
    assert seen["n"] >= 1
    imp = next(f for f in result["findings"] if f.fact.entity_key == "processes::imp::imp")
    assert imp.fact.attrs["defender_hit"] is True

    # default: defender off -> scanner never called
    seen["n"] = 0
    service.run_scan(tmp_path, db, collect=collect, ind=empty)
    assert seen["n"] == 0


def test_run_scan_counts_allowlisted(tmp_path):
    # a NEW unsigned temp proc whose path is allowlisted -> floored to INFO and
    # counted in summary.allowlisted
    def collect(ctx):
        return [Fact("processes", "processes::py::py", "process", "py",
                     {"exe": r"F:\proj\.venv\Scripts\python.exe", "from_temp": True,
                      "parent": "", "name": "py"})]
    db = tmp_path / "b.db"
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allowlist.json").write_text(
        json.dumps({"path_globs": [r"*\.venv\scripts\*"]}), encoding="utf-8")
    service.run_baseline(tmp_path, db, collect=lambda ctx: [
        Fact("processes", "processes::seed::seed", "process", "seed", {})])
    result = service.run_scan(tmp_path, db, collect=collect,
                              ind=_empty_ind(tmp_path))
    assert result["summary"]["allowlisted"] == 1
