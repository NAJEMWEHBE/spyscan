# src/spyscan/store.py
from __future__ import annotations
import sqlite3, json
from contextlib import closing
from pathlib import Path
from spyscan.facts import Fact


class BaselineStore:
    """The trusted-machine baseline in one SQLite file.

    Every call opens, commits and CLOSES its own connection: ``with
    sqlite3.connect()`` alone only commits, and on Windows the open handle kept
    baseline.db locked after each request (audit #16).
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._init()

    def _connect(self):
        return closing(sqlite3.connect(self.db_path))

    def _init(self):
        with self._connect() as c, c:
            c.execute("""CREATE TABLE IF NOT EXISTS baseline(
                entity_key TEXT PRIMARY KEY, fact_json TEXT NOT NULL)""")

    def save_baseline(self, facts: list[Fact]) -> None:
        with self._connect() as c, c:
            c.execute("DELETE FROM baseline")
            c.executemany(
                "INSERT OR REPLACE INTO baseline VALUES (?, ?)",
                [(f.entity_key, json.dumps(f.to_dict())) for f in facts],
            )

    def load_baseline(self) -> list[Fact]:
        with self._connect() as c:
            rows = c.execute("SELECT fact_json FROM baseline").fetchall()
        return [Fact.from_dict(json.loads(r[0])) for r in rows]


def baseline_count(db_path: Path) -> int | None:
    """Number of baseline facts, or None when there is no baseline yet.

    Read-only: never creates the file (a status read must not write state,
    audit #17) and closes its connection.
    """
    p = Path(db_path)
    if not p.is_file():
        return None
    try:
        with closing(sqlite3.connect(p.resolve().as_uri() + "?mode=ro", uri=True)) as c:
            n = c.execute("SELECT COUNT(*) FROM baseline").fetchone()[0]
    except sqlite3.Error:
        return None
    return n or None
