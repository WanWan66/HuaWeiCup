import re
import os
import time
from datetime import datetime
from ..model import SourceError,now

def delay(start,end):
    if start is None:return None
    try:
        value=(datetime.fromisoformat(end)-datetime.fromisoformat(start)).total_seconds()*1000
        return value if value>=0 else None
    except (TypeError,ValueError):return None

class Pipeline:
    def __init__(self,store,detector,allowed_sources):
        self.store,self.detector=store,detector;self.allowed={}
        with store.transaction() as db:
            identity=detector.fingerprint("SecretRadar-key-identity-v1")
            row=db.execute("SELECT value FROM settings WHERE name='hmac_identity'").fetchone()
            if row and row[0]!=identity:raise SourceError("hmac_key_mismatch")
            db.execute("INSERT OR IGNORE INTO settings VALUES('hmac_identity',?)",(identity,))
            for s in allowed_sources:
                if not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}",s.source_id) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}",s.source_type):
                    raise SourceError("source_metadata_invalid")
                if s.source_id in self.allowed:raise SourceError("duplicate_source_id")
                self.allowed[s.source_id]=(s.source_type,s.scope)
                binding=detector.fingerprint(s.source_type+":"+s.scope)
                name="scope_binding:"+s.source_id
                old=db.execute("SELECT value FROM settings WHERE name=?",(name,)).fetchone()
                if old and old[0]!=binding:raise SourceError("source_scope_changed_use_new_id")
                db.execute("INSERT OR IGNORE INTO settings VALUES(?,?)",(name,binding))
    def scan(self,source,mode="real",full=False):
        if self.allowed.get(source.source_id)!=(source.source_type,source.scope):raise SourceError("scope_denied")
        if mode not in {"demo","real"}:raise SourceError("mode_invalid")
        with self.store.source_lock(source.source_id):
            return self._scan(source,mode,full)
    def _scan(self,source,mode,full):
        started,timer=now(),time.perf_counter()
        documents=added=skipped=candidates=0;error=None;retry_after=None;primary_committed=False
        cursor,etag=(None,None) if full else self.store.checkpoint(source.source_id)
        version=getattr(self.detector,"version","unversioned")
        with self.store.transaction() as db:
            job=db.execute("""INSERT INTO jobs(source_id,mode,started_at,status,rule_version,worker_pid,worker_run_id)
                              VALUES(?,?,?,?,?,?,?)""",(source.source_id,mode,started,"running",version,os.getpid(),os.environ.get("SECRETRADAR_WORKER_RUN_ID"))).lastrowid
        try:
            with self.store.connect() as db:
                previous=db.execute("SELECT rule_version FROM sources WHERE source_id=?",(source.source_id,)).fetchone()
            if cursor and previous and previous[0]!=version and not full:
                raise SourceError("rule_changed_requires_full")
            batch=source.fetch(cursor,etag);first_seen=now()
            if batch.unchanged and not batch.documents:
                with self.store.connect() as db:
                    skipped=db.execute("SELECT COUNT(*) FROM documents WHERE source_id=?",(source.source_id,)).fetchone()[0]
            if batch.cursor is not None and not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}",batch.cursor):raise SourceError("unsafe_checkpoint")
            safe_etag=batch.etag if batch.etag and re.fullmatch(r'(?:W/)?"[a-f0-9]{32,64}"',batch.etag) else None
            touched=[]
            with self.store.transaction() as db:
                for doc in batch.documents:
                    path_id=self.detector.fingerprint(doc.path);content_id=self.detector.fingerprint(doc.text)
                    previous=db.execute("SELECT content_hmac,rule_version FROM documents WHERE source_id=? AND path_id=?",
                                        (source.source_id,path_id)).fetchone()
                    if not full and previous and previous[0]==content_id and previous[1]==version:
                        skipped+=1;continue
                    documents+=1
                    findings=self.detector.detect(doc.text,synthetic=(mode=="demo" and doc.synthetic));completed=now()
                    candidates+=sum(x.severity=="info" for x in findings)
                    for finding in findings:
                        if finding.severity=="info":continue
                        generated=now()
                        result=db.execute("""INSERT OR IGNORE INTO alerts(
                          source_id,source_type,path,path_id,kind,classification,severity,fingerprint,masked,line,provenance,
                          published_at,first_seen_at,scanned_at,alerted_at,collection_delay_ms,alert_delay_ms,
                          first_job_id,last_job_id,rule_version,last_seen_at,content_created_at,accessible_at,scan_completed_at,reason)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (source.source_id,source.source_type,"path-hmac:"+path_id[:16],path_id,finding.kind,finding.classification,
                           finding.severity,finding.fingerprint,finding.masked,finding.line,
                           "source-object-hmac:"+self.detector.fingerprint(doc.provenance)[:16],
                           self.publication(doc.published_at),first_seen,completed,generated,
                           delay(self.publication(doc.published_at),first_seen),delay(completed,generated),
                           job,job,version,first_seen,self.publication(getattr(doc,"created_at",None)),
                           self.publication(getattr(doc,"accessible_at",None)),completed,getattr(finding,"reason","typed_rule")))
                        new=result.rowcount==1;added+=int(new)
                        aid=db.execute("SELECT id FROM alerts WHERE source_id=? AND path_id=? AND kind=? AND fingerprint=?",
                            (source.source_id,path_id,finding.kind,finding.fingerprint)).fetchone()[0]
                        observation=db.execute("INSERT OR IGNORE INTO observations VALUES(?,?,?)",(job,aid,first_seen))
                        if observation.rowcount and not new:
                            db.execute("UPDATE alerts SET last_seen_at=?,last_job_id=?,occurrences=occurrences+1 WHERE id=?",
                                       (first_seen,job,aid))
                        if new or observation.rowcount:
                            db.execute("INSERT INTO events(alert_id,job_id,event_type,created_at) VALUES(?,?,?,?)",
                                       (aid,job,"alert_created" if new else "alert_reobserved",generated))
                        touched.append(aid)
                    db.execute("""INSERT INTO documents(source_id,path_id,content_hmac,rule_version) VALUES(?,?,?,?)
                              ON CONFLICT(source_id,path_id) DO UPDATE SET content_hmac=excluded.content_hmac,rule_version=excluded.rule_version""",
                               (source.source_id,path_id,content_id,version))
                db.execute("""INSERT INTO sources(source_id,source_type,scope_masked,cursor,etag,status,error_code,updated_at,failures,rule_version)
                            VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET
                            cursor=excluded.cursor,etag=excluded.etag,status='ok',error_code=NULL,updated_at=excluded.updated_at,
                            failures=0,next_retry_at=NULL,rule_version=excluded.rule_version""",
                           (source.source_id,source.source_type,"[ALLOWLISTED]",batch.cursor,safe_etag,"ok",None,now(),0,version))
            primary_committed=True
            # Timestamp is captured only after SQLite confirms the primary transaction commit.
            acknowledged=now()
            with self.store.transaction() as db:
                db.execute("UPDATE alerts SET persisted_at=COALESCE(persisted_at,?) WHERE id IN (SELECT alert_id FROM observations WHERE job_id=?)",
                           (acknowledged,job))
                db.execute("UPDATE events SET persisted_at=? WHERE job_id=?",(acknowledged,job))
        except Exception as exc:
            error=exc.code if isinstance(exc,SourceError) and re.fullmatch("[a-z0-9_]+",exc.code) else "scan_failed"
            retry_after=getattr(exc,"retry_after",None)
            if primary_committed:error="post_commit_ack_unavailable"
            else:added=0
            with self.store.transaction() as db:
                db.execute("""INSERT INTO sources(source_id,source_type,scope_masked,cursor,etag,status,error_code,updated_at,failures)
                 VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(source_id) DO UPDATE SET status='error',error_code=excluded.error_code,
                 updated_at=excluded.updated_at,failures=COALESCE(failures,0)+1""",
                 (source.source_id,source.source_type,"[ALLOWLISTED]",cursor,etag,"error",error,now()))
        elapsed=(time.perf_counter()-timer)*1000
        with self.store.transaction() as db:
            db.execute("""UPDATE jobs SET finished_at=?,elapsed_ms=?,documents=?,new_alerts=?,status=?,error_code=?,skipped=?,candidates=? WHERE id=?""",
                       (now(),elapsed,documents,added,"error" if error else "ok",error,skipped,candidates,job))
        return {"status":"error" if error else "ok","job_id":job,"documents":documents,"skipped":skipped,
                "candidates":candidates,"new_alerts":added,"elapsed_ms":elapsed,"error_code":error,"retry_after":retry_after}
    @staticmethod
    def publication(value):
        try:
            if not isinstance(value,str):return None
            parsed=datetime.fromisoformat(value)
            return parsed.isoformat() if parsed.tzinfo is not None else None
        except ValueError:return None
