"""One subprocess per scheduled scan: hard timeouts without unsafe thread cancellation."""
import concurrent.futures
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid
from ..model import now,SourceError
from ..sources.registry import configured

def child_scan(config,source_id,db,timeout,stop):
    run_id=uuid.uuid4().hex
    child_env=dict(os.environ);child_env["SECRETRADAR_WORKER_RUN_ID"]=run_id
    process=subprocess.Popen([sys.executable,"-m","secretradar","scan-one","--config",str(config),
                              "--source",source_id,"--db",str(db)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=child_env,start_new_session=(os.name!="nt"))
    deadline=time.monotonic()+timeout
    while process.poll() is None:
        if stop.wait(0.02) or time.monotonic()>=deadline:
            if os.name=="nt":
                subprocess.run(["taskkill","/PID",str(process.pid),"/T","/F"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            else:
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
            try:process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                if os.name!="nt":
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                process.kill();process.communicate()
            return {"status":"stopped" if stop.is_set() else "timeout","error_code":"graceful_stop" if stop.is_set() else "scan_timeout","worker_pid":process.pid,"worker_run_id":run_id}
    output=process.communicate()[0]
    try:
        value=json.loads(output.decode("utf-8"))
        return value if isinstance(value,dict) else {"status":"error","error_code":"child_invalid_output"}
    except (ValueError,UnicodeError):
        return {"status":"error","error_code":"child_failed"}

def watch(config,store,interval=60,timeout=30,max_polls=None,event_log=None,stop=None,stop_file=None):
    if not 0.1<=interval<=86400 or not 0.1<=timeout<=3600:raise SourceError("watch_timing_invalid")
    sources=configured(config)
    # Validate config scopes and HMAC binding before any worker can run.
    from .scan import Pipeline
    from ..detectors.rules import Detector
    Pipeline(store,Detector(os.environ["SECRETRADAR_HMAC_KEY"].encode()),sources)
    options=json.loads(Path(config).read_text(encoding="utf-8"))
    per_source={x["source_id"]:x for x in options.get("allowed_sources",[])}
    for spec in per_source.values():
        if not 0.1<=float(spec.get("interval_seconds",interval))<=86400 or not 0.1<=float(spec.get("timeout_seconds",timeout))<=3600:
            raise SourceError("watch_timing_invalid")
    stop=stop or threading.Event()
    old_signals={}
    if threading.current_thread() is threading.main_thread():
        for name in ("SIGINT","SIGTERM"):
            sig=getattr(signal,name,None)
            if sig is not None:
                old_signals[sig]=signal.signal(sig,lambda *_:stop.set())
    due={s.source_id:0.0 for s in sources};counts={s.source_id:0 for s in sources};failures={s.source_id:0 for s in sources}
    with store.connect() as db:
        for row in db.execute("SELECT source_id,next_retry_at FROM sources WHERE next_retry_at IS NOT NULL"):
            if row[0] in due:
                try:due[row[0]]=time.monotonic()+max(0,(datetime.fromisoformat(row[1])-datetime.now(timezone.utc)).total_seconds())
                except (ValueError,TypeError):pass
    records=[];active={};started=now()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(len(sources),4))) as pool:
            while not stop.is_set():
                if stop_file and Path(stop_file).exists():
                    stop.set();break
                for source in sources:
                    sid=source.source_id
                    if sid in active or (max_polls is not None and counts[sid]>=max_polls):continue
                    if time.monotonic()>=due[sid]:
                        limit=float(per_source[sid].get("timeout_seconds",timeout))
                        active[sid]=pool.submit(child_scan,Path(config).resolve(),sid,Path(store.path).resolve(),limit,stop)
                for sid,future in list(active.items()):
                    if not future.done():continue
                    result=future.result();active.pop(sid);counts[sid]+=1
                    good=result.get("status")=="ok"
                    failures[sid]=0 if good else failures[sid]+1
                    wait=float(per_source[sid].get("interval_seconds",interval))
                    if not good:wait=max(wait,min(60,2**min(failures[sid],6)),float(result.get("retry_after") or 0))
                    due[sid]=time.monotonic()+wait
                    next_at=(datetime.now(timezone.utc)+timedelta(seconds=wait)).isoformat()
                    with store.transaction() as db:
                        if result.get("status") in {"timeout","stopped"}:
                            db.execute("UPDATE jobs SET status=?,error_code=?,finished_at=? WHERE source_id=? AND status='running' AND worker_run_id=?",
                                (result["status"],result["error_code"],now(),sid,result.get("worker_run_id")))
                            db.execute("""INSERT INTO sources(source_id,source_type,scope_masked,status,error_code,updated_at)
                              VALUES(?,?,'[ALLOWLISTED]',?,?,?) ON CONFLICT(source_id) DO UPDATE SET status=excluded.status,
                              error_code=excluded.error_code,updated_at=excluded.updated_at""",
                              (sid,next(s.source_type for s in sources if s.source_id==sid),result["status"],result["error_code"],now()))
                        db.execute("UPDATE sources SET next_retry_at=? WHERE source_id=?",(next_at,sid))
                    records.append({"source_id":sid,"poll":counts[sid],"status":result.get("status"),"job_id":result.get("job_id"),
                                    "new_alerts":result.get("new_alerts",0),"error_code":result.get("error_code"),"next_wait_seconds":wait})
                    if event_log:store.export_events(event_log)
                if max_polls is not None and all(v>=max_polls for v in counts.values()) and not active:break
                if not sources:break
                stop.wait(0.025)
    finally:
        interrupted=stop.is_set()
        stop.set()
        for sid,future in active.items():
            result=future.result(timeout=5)
            if result.get("worker_run_id"):
                with store.transaction() as db:
                    db.execute("UPDATE jobs SET status='stopped',error_code='graceful_stop',finished_at=? WHERE status='running' AND worker_run_id=?",
                               (now(),result["worker_run_id"]))
        for sig,handler in old_signals.items():signal.signal(sig,handler)
        if event_log:store.export_events(event_log)
    return {"started_at":started,"finished_at":now(),"polls":counts,"records":records,
            "stopped":interrupted,"event_log_enabled":bool(event_log)}
