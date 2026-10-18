import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources(
 source_id TEXT PRIMARY KEY, source_type TEXT, scope_masked TEXT, cursor TEXT,
 etag TEXT, status TEXT, error_code TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS jobs(
 id INTEGER PRIMARY KEY, source_id TEXT, mode TEXT, started_at TEXT, finished_at TEXT,
 elapsed_ms REAL, documents INTEGER, new_alerts INTEGER, status TEXT, error_code TEXT);
CREATE TABLE IF NOT EXISTS documents(
 source_id TEXT, path_id TEXT, content_hmac TEXT,
 PRIMARY KEY(source_id,path_id));
CREATE TABLE IF NOT EXISTS alerts(
 id INTEGER PRIMARY KEY, source_id TEXT, source_type TEXT, path TEXT, path_id TEXT,
 kind TEXT, classification TEXT, severity TEXT, fingerprint TEXT, masked TEXT, line INTEGER,
 provenance TEXT, published_at TEXT, first_seen_at TEXT, scanned_at TEXT, alerted_at TEXT,
 collection_delay_ms REAL, alert_delay_ms REAL,
 UNIQUE(source_id,path_id,kind,fingerprint));
"""

from .round2 import StoreExtension

class Store(StoreExtension):
    def __init__(self, path):
        self.path = str(Path(path))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
        self.migrate()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connect() as db:
            yield db

    def checkpoint(self, source_id):
        with self.connect() as db:
            row = db.execute("SELECT cursor,etag FROM sources WHERE source_id=?", (source_id,)).fetchone()
            return (row["cursor"], row["etag"]) if row else (None, None)

    def snapshot(self):
        with self.connect() as db:
            alerts = [dict(r) for r in db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 500")]
            sources = [dict(r) for r in db.execute("SELECT source_id,source_type,status,error_code,updated_at,failures,next_retry_at,rule_version FROM sources")]
            jobs = [dict(r) for r in db.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 100")]
            groups = [dict(r) for r in db.execute("SELECT kind,count(*) AS count FROM alerts GROUP BY kind")]
            count = db.execute("SELECT count(*) FROM alerts").fetchone()[0]
        return {"alerts": alerts, "sources": sources, "jobs": jobs, "by_type": groups,
                "metrics": {"alerts": count, "sources": len(sources), "jobs_shown": len(jobs)},
                "credential_validity": "never_validated"}
