"""Evaluate frozen synthetic labels without using detector output to create truth."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"workspace"))
from secretradar.evaluation.round2_dataset import corpus,manifest
from secretradar.detectors.rules import Detector,RULE_VERSION
def score(detector,samples):
    totals={"TP":0,"FP":0,"FN":0};categories={};errors=[];candidates=0
    for sample in samples:
        findings=detector.detect(sample["text"])
        predicted={x.kind for x in findings if x.severity!="info"}
        candidates+=sum(x.severity=="info" for x in findings)
        expected=set(sample["expected"])
        for category in expected|predicted:
            m=categories.setdefault(category,{"TP":0,"FP":0,"FN":0})
            m["TP"]+=int(category in expected and category in predicted)
            m["FP"]+=int(category in predicted and category not in expected)
            m["FN"]+=int(category in expected and category not in predicted)
        totals["TP"]+=len(expected&predicted);totals["FP"]+=len(predicted-expected);totals["FN"]+=len(expected-predicted)
        if predicted!=expected:errors.append({"id":sample["id"],"family":sample["family"],"expected":sorted(expected),"predicted":sorted(predicted)})
    def finish(m):
        p=m["TP"]/(m["TP"]+m["FP"]) if m["TP"]+m["FP"] else 0
        r=m["TP"]/(m["TP"]+m["FN"]) if m["TP"]+m["FN"] else 0
        return dict(m,Precision=p,Recall=r,F1=2*p*r/(p+r) if p+r else 0)
    return {"documents":len(samples),"metrics":finish(totals),"per_category":{k:finish(v) for k,v in categories.items()},
            "informational_candidates_not_alerted":candidates,"mismatches":errors}
def run(split,verify=False):
    frozen=json.loads((ROOT/"reports/ROUND2_DATASET_FROZEN.json").read_text())
    assert frozen["samples"]==manifest()["samples"],"Dataset changed after freeze"
    assert frozen["generator_sha256"]==hashlib.sha256((ROOT/"workspace/secretradar/evaluation/round2_dataset.py").read_bytes()).hexdigest()
    result_path=ROOT/"reports"/("ROUND2_"+split.upper()+"_RESULTS.json")
    if split=="holdout" and result_path.exists() and not verify:raise SystemExit("Holdout already evaluated; preserve first result")
    spec=importlib.util.spec_from_file_location("round1_frozen_detector",ROOT/"notes/round2_start/round1_rules.py")
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    key=b"TEST_ONLY_EVALUATION_KEY_NOT_REAL_00000"
    samples=corpus(split)
    result={"split":split,"dataset":"frozen synthetic truth","rule_version":RULE_VERSION,
            "primary_metric":"type-level actionable alerts; informational candidate counts separately disclosed",
            "before":score(module.Detector(key),samples),"after":score(Detector(key),samples)}
    if verify:
        assert result_path.exists() and json.loads(result_path.read_text())==result,"Recorded evaluation does not reproduce"
    else:
        result_path.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps({"split":split,"before":result["before"]["metrics"],"after":result["after"]["metrics"],
                      "mismatch_count":len(result["after"]["mismatches"])}))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--split",choices=["development","holdout"],required=True);p.add_argument("--verify-recorded",action="store_true")
    args=p.parse_args();run(args.split,args.verify_recorded)
