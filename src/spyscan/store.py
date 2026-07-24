# src/spyscan/store.py
from __future__ import annotations
import sqlite3, json
from pathlib import Path
from spyscan.facts import Fact

class BaselineStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._init()

    def _init(self):
        with sqlite3.connect(self.db_path) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS baseline(
                entity_key TEXT PRIMARY KEY, fact_json TEXT NOT NULL)""")

    def save_baseline(self, facts: list[Fact]) -> None:
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM baseline")
            c.executemany(
                "INSERT OR REPLACE INTO baseline VALUES (?, ?)",
                [(f.entity_key, json.dumps(f.to_dict())) for f in facts],
            )

    def load_baseline(self) -> list[Fact]:
        with sqlite3.connect(self.db_path) as c:
            rows = c.execute("SELECT fact_json FROM baseline").fetchall()
        return [Fact.from_dict(json.loads(r[0])) for r in rows]
