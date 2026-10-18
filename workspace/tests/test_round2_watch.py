import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import pytest
from secretradar.evaluation.controlled_server import ControlledServer
from secretradar.evaluation.fixtures import samples
from secretradar.pipeline.watch import watch
from secretradar.storage.sqlite import Store

def configured_server(tmp_path,server,two=False):
    sources=[{"source_id":"feed","source_type":"controlled_http","scope":server.base+"/feed"}]
    if two:sources.append({"source_id":"wiki","source_type":"mediawiki","scope":server.base+"/wiki/api.php","local_protocol":True})
    path=tmp_path/"authorized.json";path.write_text(json.dumps({"mode":"demo","allowed_sources":sources}));return path
def test_multi_source_actual_worker_and_restart(tmp_path,monkeypatch):
    monkeypatch.setenv("SECRETRADAR_HMAC_KEY","TEST_ONLY_WORKER_RESTART_KEY_000000000")
    with ControlledServer() as server:
        server.publish(samples()[0][1]);config=configured_server(tmp_path,server,True)
        store=Store(tmp_path/"worker.db");events=tmp_path/"events.jsonl"
        first=watch(config,store,interval=.1,timeout=8,max_polls=2,event_log=events)
        assert first["polls"]=={"feed":2,"wiki":2}
        assert sum(r["new_alerts"] for r in first["records"])==2
        second=watch(config,Store(store.path),interval=.1,timeout=8,max_polls=1,event_log=events)
        assert sum(r["new_alerts"] for r in second["records"])==0
        assert len(events.read_text().splitlines())==2
def test_graceful_stop_file(tmp_path,monkeypatch):
    monkeypatch.setenv("SECRETRADAR_HMAC_KEY","TEST_ONLY_GRACEFUL_STOP_KEY_0000000000")
    with ControlledServer() as server:
        config=configured_server(tmp_path,server);store=Store(tmp_path/"worker.db")
        stop=tmp_path/"STOP"
        results=[]
        thread=threading.Thread(target=lambda:results.append(watch(config,store,interval=.1,timeout=8,stop_file=stop)))
        thread.start()
        deadline=time.monotonic()+10
        while not store.snapshot()["jobs"] and time.monotonic()<deadline:time.sleep(.03)
        stop.write_text("STOP");thread.join(10)
        assert not thread.is_alive() and results[0]["stopped"]
        with store.connect() as db:assert db.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()[0]==0
def test_source_timeout_does_not_advance_checkpoint(tmp_path,monkeypatch):
    monkeypatch.setenv("SECRETRADAR_HMAC_KEY","TEST_ONLY_TIMEOUT_KEY_0000000000000000")
    with ControlledServer() as server:
        config=tmp_path/"slow.json"
        config.write_text(json.dumps({"allowed_sources":[{"source_id":"slow","source_type":"controlled_http","scope":server.base+"/slow"}]}))
        store=Store(tmp_path/"worker.db")
        value=watch(config,store,interval=.1,timeout=.8,max_polls=1)
        assert value["records"][0]["error_code"]=="scan_timeout"
        assert store.checkpoint("slow")==(None,None)
        time.sleep(2.2)
        assert store.checkpoint("slow")==(None,None)
        with store.connect() as db:assert db.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()[0]==0
def test_retry_backoff_and_next_retry_persisted(tmp_path,monkeypatch):
    monkeypatch.setenv("SECRETRADAR_HMAC_KEY","TEST_ONLY_RETRY_KEY_000000000000000000")
    config=tmp_path/"broken.json"
    config.write_text(json.dumps({"allowed_sources":[{"source_id":"bad_git","source_type":"local_git","scope":str(tmp_path/"missing")}]}))
    store=Store(tmp_path/"worker.db")
    value=watch(config,store,interval=.1,timeout=8,max_polls=2)
    assert [r["next_wait_seconds"] for r in value["records"]]==[2,4]
    assert all(r["status"]=="error" for r in value["records"])
    assert store.snapshot()["sources"][0]["failures"]==2
    assert store.snapshot()["sources"][0]["next_retry_at"]
