"""Audit #16 + #17: the baseline store releases its file; reading creates nothing.

#16: ``with sqlite3.connect()`` commits but never closes, so on Windows
     baseline.db stayed locked (WinError 32) after every request.
#17: GET /api/status opened BaselineStore, whose constructor CREATES the DB,
     so a read endpoint wrote <repo>/baseline.db (and the launch test did it
     against the real repo root).
"""
from __future__ import annotations
import os

from spyscan.app import server
from spyscan.facts import Fact
from spyscan.store import BaselineStore


def _facts(n=2):
    return [Fact("processes", f"processes::{i}", "process", str(i), {}) for i in range(n)]


def test_store_releases_the_db_file_after_each_call(tmp_path):
    db = tmp_path / "b.db"
    store = BaselineStore(db)
    store.save_baseline(_facts())
    assert len(store.load_baseline()) == 2
    os.rename(db, tmp_path / "moved.db")      # WinError 32 while a handle is open


def test_status_does_not_create_a_baseline_db(tmp_path):
    db = tmp_path / "b.db"
    app = server.create_app(root=tmp_path, db=db)
    c = app.test_client()
    c.environ_base["HTTP_X_SPYSCAN_TOKEN"] = app.config["SPYSCAN_TOKEN"]
    d = c.get("/api/status").get_json()
    assert d["baseline_exists"] is False
    assert not db.exists()


def test_status_counts_an_existing_baseline_and_releases_it(tmp_path):
    db = tmp_path / "b.db"
    BaselineStore(db).save_baseline(_facts(3))
    app = server.create_app(root=tmp_path, db=db)
    c = app.test_client()
    c.environ_base["HTTP_X_SPYSCAN_TOKEN"] = app.config["SPYSCAN_TOKEN"]
    assert c.get("/api/status").get_json()["baseline_count"] == 3
    os.rename(db, tmp_path / "moved.db")
