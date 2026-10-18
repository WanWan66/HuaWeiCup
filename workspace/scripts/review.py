"""Reproduce offline evidence. Synthetic fixtures only; key supplied in environment."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0,str(ROOT))
from secretradar.detectors.rules import Detector
from secretradar.evaluation.fixtures import Synthetic,git_repo,oci_archive
from secretradar.pipeline.scan import Pipeline
from secretradar.sources.local import LocalGit,OCIArchive
from secretradar.storage.sqlite import Store

def main():
    if len(os.environ.get("SECRETRADAR_HMAC_KEY","").encode())<32:
        raise SystemExit("Supply an independent SECRETRADAR_HMAC_KEY")
    report=ROOT.parent/"reports";report.mkdir(exist_ok=True)
    runtime=ROOT/"runtime"/("review-"+str(time.time_ns()))
    runtime.mkdir(parents=True)
    detector=Detector(os.environ["SECRETRADAR_HMAC_KEY"].encode())
    source=Synthetic();demo_store=Store(runtime/"demo.db")
    demo=Pipeline(demo_store,detector,[source]).scan(source,"demo")
    # Actual CLI invocation is checked too, using the same independently supplied key.
    completed=subprocess.run([sys.executable,"-m","secretradar","demo","--db",str(runtime/"cli-demo.db")],
                             capture_output=True,text=True,check=True)
    cli=json.loads(completed.stdout)
    subprocess.run([sys.executable,"-m","secretradar","evaluate","--output",str(report/"evaluation.json")],
                   check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    git_repo(runtime/"controlled-git")
    oci_archive(runtime/"controlled-oci.tar")
    real_sources=[LocalGit("controlled_git",runtime/"controlled-git"),
                  OCIArchive("controlled_oci",runtime/"controlled-oci.tar")]
    local_store=Store(runtime/"local-source.db")
    pipeline=Pipeline(local_store,detector,real_sources)
    integrations=[]
    for s in real_sources:
        first=pipeline.scan(s)
        repeated=pipeline.scan(s)
        assert first["status"]=="ok" and first["new_alerts"]==1
        assert repeated["status"]=="ok" and repeated["new_alerts"]==0 and repeated["documents"]==0
        integrations.append({"source_id":s.source_id,"source_type":s.source_type,
                             "input":"explicitly controlled synthetic fixture","initial":first,"repeat":repeated})
    (report/"demo-dashboard.json").write_text(json.dumps({"mode":"demo",**demo_store.snapshot()},indent=2),encoding="utf-8")
    (report/"local-source-evidence.json").write_text(json.dumps({"integrations":integrations,"sanitized_snapshot":local_store.snapshot()},indent=2),encoding="utf-8")
    (report/"demo-run.json").write_text(json.dumps({"demo":demo,"cli":cli,"db_relative":str((runtime/"demo.db").relative_to(ROOT))},indent=2),encoding="utf-8")
    print(json.dumps({"demo":demo,"local_integrations":len(integrations),"db_relative":str((runtime/"demo.db").relative_to(ROOT))}))
if __name__=="__main__":
    main()
