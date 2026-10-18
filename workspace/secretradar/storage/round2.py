import json
import os
from pathlib import Path
from contextlib import contextmanager
from ..model import SourceError,now

class StoreExtension:
    def migrate(self):
        additions={
            "jobs":{"rule_version":"TEXT","skipped":"INTEGER DEFAULT 0","candidates":"INTEGER DEFAULT 0","worker_pid":"INTEGER","worker_run_id":"TEXT"},
            "documents":{"rule_version":"TEXT"},
            "sources":{"failures":"INTEGER DEFAULT 0","next_retry_at":"TEXT","rule_version":"TEXT"},
            "alerts":{"first_job_id":"INTEGER","last_job_id":"INTEGER","rule_version":"TEXT",
                      "last_seen_at":"TEXT","occurrences":"INTEGER DEFAULT 1","state":"TEXT DEFAULT 'open'",
                      "content_created_at":"TEXT","accessible_at":"TEXT","scan_completed_at":"TEXT","persisted_at":"TEXT","reason":"TEXT"}}
        with self.transaction() as db:
            for table,columns in additions.items():
                existing={r[1] for r in db.execute("PRAGMA table_info("+table+")")}
                for name,kind in columns.items():
                    if name not in existing:db.execute("ALTER TABLE "+table+" ADD COLUMN "+name+" "+kind)
            db.executescript("""
            CREATE TABLE IF NOT EXISTS observations(job_id INTEGER,alert_id INTEGER,observed_at TEXT,PRIMARY KEY(job_id,alert_id));
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,alert_id INTEGER,job_id INTEGER,event_type TEXT,created_at TEXT,persisted_at TEXT);
            CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY,value TEXT);
            """)

            if not db.execute("SELECT 1 FROM settings WHERE name='round2_legacy_review_migration'").fetchone():
                db.execute("UPDATE alerts SET state='needs_review' WHERE rule_version IS NULL AND first_job_id IS NULL")
                db.execute("INSERT INTO settings VALUES('round2_legacy_review_migration','done')")

    @contextmanager
    def source_lock(self,source_id):
        directory=Path(self.path).parent/".locks";directory.mkdir(exist_ok=True)
        with (directory/(source_id+".lock")).open("a+b") as file:
            file.seek(0,2)
            if file.tell()==0:file.write(b"0");file.flush()
            file.seek(0)
            try:
                if os.name=="nt":
                    import msvcrt
                    msvcrt.locking(file.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:raise SourceError("source_busy") from None
            try:yield
            finally:
                if os.name=="nt":
                    file.seek(0);msvcrt.locking(file.fileno(),msvcrt.LK_UNLCK,1)
                else:fcntl.flock(file.fileno(),fcntl.LOCK_UN)

    def export_events(self,path):
        with self.connect() as db:
            rows=[dict(r) for r in db.execute("""SELECT e.id AS event_id,e.alert_id,e.job_id,e.event_type,e.created_at,e.persisted_at,
              a.source_id,a.source_type,a.kind,a.classification,a.severity,a.masked,a.fingerprint,a.state
              FROM events e JOIN alerts a ON a.id=e.alert_id ORDER BY e.id""")]
        target=Path(path);target.parent.mkdir(parents=True,exist_ok=True)
        temporary=target.with_suffix(target.suffix+"."+str(os.getpid())+".tmp")
        temporary.write_text("".join(json.dumps(r)+"\n" for r in rows),encoding="utf-8")
        os.replace(temporary,target)
        return len(rows)

    def lifecycle(self,alert_id,state):
        if state not in {"open","acknowledged","resolved"}:raise SourceError("invalid_alert_state")
        with self.transaction() as db:
            row=db.execute("SELECT id FROM alerts WHERE id=?",(alert_id,)).fetchone()
            if not row:raise SourceError("alert_not_found")
            db.execute("UPDATE alerts SET state=? WHERE id=?",(state,alert_id))
            event_id=db.execute("INSERT INTO events(alert_id,event_type,created_at) VALUES(?,?,?)",(alert_id,"state_"+state,now())).lastrowid
        with self.transaction() as db:
            db.execute("UPDATE events SET persisted_at=? WHERE id=?",(now(),event_id))
