import json
import os
import threading
from pathlib import Path
import pytest
from secretradar.model import SourceError
from secretradar.evaluation.fixtures import Synthetic,git_repo,samples
from secretradar.pipeline.scan import Pipeline
from secretradar.pipeline.locator import locate
from secretradar.sources.local import LocalGit
def test_events_are_persistent_and_redacted(store,detector,tmp_path):
    s=Synthetic();p=Pipeline(store,detector,[s]);r=p.scan(s,"demo")
    path=tmp_path/"events.jsonl"
    assert store.export_events(path)==7
    values=[json.loads(x) for x in path.read_text().splitlines()]
    assert all(x["job_id"]==r["job_id"] and x["persisted_at"] for x in values)
    assert samples()[0][1].split("=")[1] not in path.read_text()
    before=path.read_bytes();store.export_events(path);assert before==path.read_bytes()
def test_reobservation_and_lifecycle(store,detector):
    s=Synthetic();p=Pipeline(store,detector,[s])
    p.scan(s,"demo");p.scan(s,"demo",full=True)
    alert=store.snapshot()["alerts"][0]
    assert alert["occurrences"]==2 and alert["first_job_id"]!=alert["last_job_id"]
    store.lifecycle(alert["id"],"resolved")
    assert store.snapshot()["alerts"][0]["state"]=="resolved"
def test_persistence_after_scan_completion(store,detector):
    s=Synthetic();Pipeline(store,detector,[s]).scan(s,"demo")
    alert=store.snapshot()["alerts"][0]
    assert alert["scan_completed_at"]<=alert["alerted_at"]<=alert["persisted_at"]
def test_scope_rebinding_rejected(store,detector):
    s=Synthetic();Pipeline(store,detector,[s]);s.scope="memory://different"
    with pytest.raises(SourceError,match="source_scope_changed"):
        Pipeline(store,detector,[s])
def test_same_source_mutex(store,detector):
    s=Synthetic();p=Pipeline(store,detector,[s]);results=[]
    with store.source_lock(s.source_id):
        thread=threading.Thread(target=lambda: _try_scan(p,s,results));thread.start();thread.join(3)
    assert results==["source_busy"]
def _try_scan(p,s,results):
    try:p.scan(s)
    except SourceError as exc:results.append(exc.code)
def test_controlled_rule_change_requires_full(store,detector):
    s=Synthetic();p=Pipeline(store,detector,[s]);p.scan(s,"demo")
    detector.version="a-different-test-version"
    result=Pipeline(store,detector,[s]).scan(s,"demo")
    assert result["error_code"]=="rule_changed_requires_full"
    assert Pipeline(store,detector,[s]).scan(s,"demo",full=True)["status"]=="ok"
def test_operator_locator_no_public_path(store,detector,tmp_path):
    repo=tmp_path/"repository";git_repo(repo)
    source=LocalGit("owned",repo);Pipeline(store,detector,[source]).scan(source)
    alert=store.snapshot()["alerts"][0]
    target=locate(source,detector,alert["path_id"])
    assert target==repo/"controlled.txt"
    assert str(repo) not in json.dumps(store.snapshot())
def test_legacy_database_migration(detector,tmp_path):
    import sqlite3
    from secretradar.storage.sqlite import SCHEMA,Store
    path=tmp_path/"legacy.db"
    with sqlite3.connect(path) as db:db.executescript(SCHEMA)
    s=Store(path)
    with s.connect() as db:
        assert "persisted_at" in {x[1] for x in db.execute("PRAGMA table_info(alerts)")}


def test_legacy_checkpoint_requires_explicit_rescan(tmp_path,detector):
    import sqlite3
    from secretradar.storage.sqlite import SCHEMA,Store
    path=tmp_path/"legacy-checkpoint.db"
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO sources VALUES(?,?,?,?,?,?,?,?)",
                   ("controlled_demo","synthetic","[ALLOWLISTED]","fixture-v1",None,"ok",None,None))
    s=Store(path);source=Synthetic();pipeline=Pipeline(s,detector,[source])
    assert pipeline.scan(source)["error_code"]=="rule_changed_requires_full"
    assert pipeline.scan(source,full=True)["status"]=="ok"


def test_cli_reads_utf8_authorized_path(tmp_path,monkeypatch):
    import subprocess,sys,os
    repo=tmp_path/"合法仓库";git_repo(repo)
    config=tmp_path/"authorized-utf8.json"
    config.write_text(json.dumps({"mode":"real","allowed_sources":[{"source_id":"utf8_repo","source_type":"local_git","scope":str(repo)}]},ensure_ascii=False),encoding="utf-8")
    monkeypatch.setenv("SECRETRADAR_HMAC_KEY","TEST_ONLY_UTF8_CONFIG_KEY_000000000000")
    result=subprocess.run([sys.executable,"-m","secretradar","scan","--config",str(config),"--db",str(tmp_path/"utf8.db")],
                          capture_output=True,timeout=15)
    assert result.returncode==0
    assert json.loads(result.stdout)["results"][0]["new_alerts"]==1
