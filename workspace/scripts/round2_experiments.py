"""Actual controlled polling and real filesystem scale measurements."""
import argparse
from datetime import datetime
import json
import math
import os
from pathlib import Path
import random
import statistics
import string
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[2];WORK=ROOT/"workspace"
os.chdir(WORK);sys.path.insert(0,str(WORK))
from secretradar.detectors.rules import Detector,RULE_VERSION
from secretradar.evaluation.controlled_server import ControlledServer
from secretradar.evaluation.fixtures import samples
from secretradar.evaluation.resources import memory
from secretradar.model import now
from secretradar.pipeline.scan import Pipeline
from secretradar.sources.controlled_directory import ControlledDirectory
from secretradar.sources.remote import GitHub,MediaWiki
from secretradar.storage.sqlite import Store

def summary(values):
    return {"n":len(values),"mean_ms":statistics.mean(values),"median_ms":statistics.median(values),
            "p95_ms_nearest_rank":sorted(values)[math.ceil(.95*len(values))-1]}
def milliseconds(a,b):return (datetime.fromisoformat(b)-datetime.fromisoformat(a)).total_seconds()*1000
def command(*args,timeout=30):
    p=subprocess.run([sys.executable,"-m","secretradar",*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout)
    result=json.loads(p.stdout.decode())
    if p.returncode:raise RuntimeError("controlled_cli_failed")
    return result

def timing(folder,detector):
    results=[]
    for index,interval in enumerate([.25,1.0]):
        directory=folder/("timing-"+str(index));directory.mkdir()
        store=Store(directory/"watch.db");config=directory/"authorized.json";stop=directory/"stop";events=directory/"events.jsonl"
        rng=random.Random(903+index)
        with ControlledServer() as server:
            config.write_text(json.dumps({"mode":"demo","allowed_sources":[{"source_id":"time_feed","source_type":"controlled_http","scope":server.base+"/feed"}]}))
            process=subprocess.Popen([sys.executable,"-m","secretradar","watch","--config",str(config),"--db",store.path,
                "--interval",str(interval),"--timeout","8","--max-polls","100","--event-log",str(events),"--stop-file",str(stop)],
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            records=[]
            try:
                deadline=time.monotonic()+12
                while time.monotonic()<deadline:
                    if store.snapshot()["sources"]:break
                    if process.poll() is not None:raise RuntimeError("watch_exited_early")
                    time.sleep(.03)
                else:raise RuntimeError("watch_start_timeout")
                for round_id in range(10):
                    time.sleep(rng.uniform(.02,interval*.8))
                    created=now()
                    token="SRTEST_"+ "".join(rng.choices(string.ascii_letters+string.digits,k=32))
                    publication=server.publish("api_token="+token,created)
                    fingerprint=detector.fingerprint(token);deadline=time.monotonic()+12
                    while time.monotonic()<deadline:
                        with store.connect() as db:
                            row=db.execute("SELECT id,first_seen_at,scan_completed_at,alerted_at,persisted_at,first_job_id FROM alerts WHERE fingerprint=? AND persisted_at IS NOT NULL",(fingerprint,)).fetchone()
                        if row:break
                        time.sleep(.01)
                    else:raise RuntimeError("automatic_alert_timeout")
                    record={**publication,**dict(row),"external_delivered_at":None}
                    record.update(accessible_to_first_seen_ms=milliseconds(publication["accessible_at"],row["first_seen_at"]),
                                  accessible_to_persisted_ms=milliseconds(publication["accessible_at"],row["persisted_at"]))
                    records.append(record)
                stop.write_text("STOP")
                output=process.communicate(timeout=15)[0]
                watcher=json.loads(output.decode())
                if process.returncode:raise RuntimeError("watch_failed")
            finally:
                if process.poll() is None:
                    stop.write_text("STOP")
                    try:process.communicate(timeout=12)
                    except subprocess.TimeoutExpired:process.terminate();process.communicate()
            restart=command("watch","--config",config,"--db",store.path,"--interval",".1","--timeout","8","--max-polls","3","--event-log",events)
            with store.connect() as db:
                alert_count=db.execute("SELECT count(*) FROM alerts").fetchone()[0]
                running=db.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()[0]
            assert alert_count==10 and running==0 and all(x["new_alerts"]==0 for x in restart["records"])
            result={"evidence_class":"LOCAL_CONTROLLED","configured_interval_seconds":interval,
                    "schedule":"fixed delay after previous child scan completes; includes worker startup overhead",
                    "rounds":len(records),"polls":watcher["polls"],"automatic_alerts":alert_count,
                    "graceful_stop":watcher["stopped"],"unfinished_jobs":running,"restart":restart,
                    "accessible_to_first_seen":summary([r["accessible_to_first_seen_ms"] for r in records]),
                    "accessible_to_persisted":summary([r["accessible_to_persisted_ms"] for r in records]),
                    "events":len(events.read_text().splitlines()),"records":records,"watch_records":watcher["records"],
                    "remote_authorized_timing":None}
            results.append(result)
            print(json.dumps({"timing_interval":interval,"rounds":len(records),"polls":watcher["polls"]}),flush=True)
    (ROOT/"reports/ROUND2_TIMING.json").write_text(json.dumps(results,indent=2),encoding="utf-8")

def protocol(folder,detector):
    store=Store(folder/"protocol.db")
    with ControlledServer() as server:
        github=GitHub("local_github","unit/fixture",api_base=server.base+"/github")
        wiki=MediaWiki("local_wiki",server.base+"/wiki/api.php",local_protocol=True)
        pipeline=Pipeline(store,detector,[github,wiki])
        initial=[pipeline.scan(github),pipeline.scan(wiki)]
        server.github_stage=2;server.publish(samples()[0][1])
        changed=[pipeline.scan(github),pipeline.scan(wiki)]
        repeated=[pipeline.scan(github),pipeline.scan(wiki)]
        assert all(x["new_alerts"]==1 and x["status"]=="ok" for x in changed)
        value={"evidence_class":"LOCAL_INTEGRATION_TESTED","transport":"actual loopback HTTP",
               "initial":initial,"changed":changed,"repeated":repeated,"requests":server.requests,
               "github_case":"new commit containing synthetic token followed by deletion before next polling"}
    (ROOT/"reports/ROUND2_PROTOCOL_EVIDENCE.json").write_text(json.dumps(value,indent=2),encoding="utf-8")

def scale(folder,detector,sizes):
    results=[]
    for size in sizes:
        directory=folder/("files-"+str(size));directory.mkdir()
        (directory/".secretradar-synthetic-fixture").write_text("SYNTHETIC_ONLY")
        rng=random.Random(size+991);total=0;expected=0
        for i in range(size):
            text="# controlled synthetic fixture only\nrecord_number="+str(i)+"\n"+("# ordinary application settings\n"*8)
            if i%10==0:
                text+="api_token=SRTEST_"+ "".join(rng.choices(string.ascii_letters+string.digits,k=32))+"\n";expected+=1
            raw=text.encode();(directory/(str(i)+".txt")).write_bytes(raw);total+=len(raw)
        repeats=[]
        for repeat in range(3):
            store=Store(folder/("scale-"+str(size)+"-"+str(repeat)+".db"));initial_db=Path(store.path).stat().st_size
            source=ControlledDirectory("scale_files",directory);pipeline=Pipeline(store,detector,[source])
            wall,cpu=time.perf_counter(),time.process_time()
            scan=pipeline.scan(source,"demo")
            seconds=time.perf_counter()-wall;cpu_seconds=time.process_time()-cpu
            rss=memory()
            incremental=pipeline.scan(source,"demo")
            assert scan["status"]=="ok" and scan["documents"]==size and scan["new_alerts"]==expected
            assert incremental["documents"]==0 and incremental["skipped"]==size and incremental["new_alerts"]==0
            repeats.append({"wall_seconds":seconds,"cpu_seconds":cpu_seconds,"cpu_one_core_equivalent_percent":cpu_seconds/seconds*100,
                "files_per_second":size/seconds,"bytes_per_second":total/seconds,**rss,
                "scan":scan,"incremental":incremental,"db_initial_bytes":initial_db,
                "db_final_bytes":Path(store.path).stat().st_size,"db_growth_bytes":Path(store.path).stat().st_size-initial_db})
        result={"files":size,"input_bytes":total,"expected_alerts":expected,"repeats":repeats,
            "median_wall_seconds":statistics.median(x["wall_seconds"] for x in repeats),
            "median_files_per_second":statistics.median(x["files_per_second"] for x in repeats),
            "median_cpu_one_core_equivalent_percent":statistics.median(x["cpu_one_core_equivalent_percent"] for x in repeats),
            "median_rss_bytes":statistics.median(x["rss_bytes"] for x in repeats),
            "median_db_growth_bytes":statistics.median(x["db_growth_bytes"] for x in repeats),
            "scope":"real local filesystem controlled_directory + detector + SQLite; not GitHub or local Git collector throughput",
            "incremental_note":"reads files and computes HMAC then skips detection; filesystem cache not cleared"}
        results.append(result);print(json.dumps({"scale_files":size,"median_seconds":result["median_wall_seconds"]}),flush=True)
        (ROOT/"reports/ROUND2_PERFORMANCE.json").write_text(json.dumps(results,indent=2),encoding="utf-8")
def main():
    p=argparse.ArgumentParser();p.add_argument("kind",choices=["timing","scale"]);p.add_argument("--sizes",default="100,1000,10000")
    args=p.parse_args()
    key=os.environ.get("SECRETRADAR_HMAC_KEY","").encode();detector=Detector(key)
    provenance={"git_commit":subprocess.check_output(["git","-C",str(ROOT),"rev-parse","HEAD"],text=True).strip(),
                "rule_version":RULE_VERSION,"started_at":now(),"kind":args.kind,
                "module_sha256":{name:__import__("hashlib").sha256((WORK/name).read_bytes()).hexdigest()
                 for name in ["secretradar/pipeline/scan.py","secretradar/pipeline/watch.py","secretradar/detectors/rules.py"]}}
    (ROOT/("reports/ROUND2_"+args.kind.upper()+"_PROVENANCE.json")).write_text(json.dumps(provenance,indent=2),encoding="utf-8")
    folder=Path("runtime")/("round2-"+args.kind+"-"+str(time.time_ns()));folder.mkdir(parents=True)
    if args.kind=="timing":protocol(folder,detector);timing(folder,detector)
    else:scale(folder,detector,[int(s) for s in args.sizes.split(",")])
if __name__=="__main__":main()
