import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from secretradar.evaluation.controlled_server import ControlledServer
from secretradar.evaluation.fixtures import samples
from secretradar.sources.remote import GitHub,MediaWiki
from secretradar.sources.controlled import ControlledHTTP
from secretradar.pipeline.scan import Pipeline

def test_github_actual_http_increment_including_deleted_commit(store,detector):
    with ControlledServer() as server:
        source=GitHub("local_github","unit/fixture",api_base=server.base+"/github")
        pipeline=Pipeline(store,detector,[source])
        assert pipeline.scan(source)["new_alerts"]==0
        server.github_stage=2
        result=pipeline.scan(source)
        assert result["status"]=="ok" and result["new_alerts"]==1
        assert pipeline.scan(source)["new_alerts"]==0
        assert server.requests>=6
def test_wiki_actual_http_and_increment(store,detector):
    with ControlledServer() as server:
        source=MediaWiki("local_wiki",server.base+"/wiki/api.php",local_protocol=True)
        pipeline=Pipeline(store,detector,[source])
        assert pipeline.scan(source)["documents"]==0
        server.publish(samples()[0][1])
        assert pipeline.scan(source)["new_alerts"]==1
        assert pipeline.scan(source)["skipped"]==1
def test_loopback_feed_metadata(store,detector):
    with ControlledServer() as server:
        server.publish(samples()[0][1])
        source=ControlledHTTP("controlled_feed",server.base+"/feed")
        assert Pipeline(store,detector,[source]).scan(source,"demo")["new_alerts"]==1
        a=store.snapshot()["alerts"][0]
        assert a["content_created_at"]<=a["accessible_at"]<=a["first_seen_at"]<=a["scan_completed_at"]<=a["persisted_at"]
def test_watch_hard_timeout_process(store,tmp_path,monkeypatch):
    from secretradar.pipeline.watch import watch
    monkeypatch.setenv("SECRETRADAR_HMAC_KEY","TEST_ONLY_WATCH_KEY_NOT_REAL_000000000")
    with ControlledServer() as server:
        config=tmp_path/"config.json"
        config.write_text(json.dumps({"allowed_sources":[{"source_id":"slow_source","source_type":"controlled_http","scope":server.base+"/slow"}]}))
        result=watch(config,store,interval=.2,timeout=.5,max_polls=1)
        assert result["records"][0]["status"]=="timeout"
        assert store.checkpoint("slow_source")==(None,None)
def test_watch_empty_allowlist(store,tmp_path,monkeypatch):
    from secretradar.pipeline.watch import watch
    monkeypatch.setenv("SECRETRADAR_HMAC_KEY","TEST_ONLY_WATCH_KEY_NOT_REAL_000000000")
    config=tmp_path/"config.json";config.write_text('{"allowed_sources":[]}')
    assert watch(config,store,max_polls=1)["polls"]=={}
def test_custom_github_api_rejects_foreign_host():
    with pytest.raises(Exception):GitHub("bad","unit/fixture",api_base="https://not-authorized.invalid")
