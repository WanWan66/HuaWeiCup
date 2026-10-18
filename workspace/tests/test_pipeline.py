import json
import sqlite3
import pytest
from secretradar.model import Batch,Document,SourceError
from secretradar.pipeline.scan import Pipeline
from secretradar.evaluation.fixtures import Synthetic,samples

def test_deny_by_default(store,detector):
    with pytest.raises(SourceError,match="scope_denied"):
        Pipeline(store,detector,[]).scan(Synthetic())

def test_exact_scope(store,detector):
    source=Synthetic();pipeline=Pipeline(store,detector,[source]);source.scope="other"
    with pytest.raises(SourceError):
        pipeline.scan(source)

def test_incremental_idempotency(store,detector):
    s=Synthetic();p=Pipeline(store,detector,[s])
    first=p.scan(s,"demo");second=p.scan(s,"demo")
    assert first["new_alerts"]==7
    assert second["new_alerts"]==0 and second["documents"]==0
    assert len(store.snapshot()["alerts"])==7

def test_full_rescan_dedupe(store,detector):
    s=Synthetic();p=Pipeline(store,detector,[s])
    p.scan(s,"demo");r=p.scan(s,"demo",full=True)
    assert r["documents"]==14 and r["new_alerts"]==0

def test_no_raw_database_or_json(store,detector):
    s=Synthetic();Pipeline(store,detector,[s]).scan(s,"demo")
    raw=samples()[0][1].split("=")[1]
    assert raw.encode() not in __import__("pathlib").Path(store.path).read_bytes()
    assert raw not in json.dumps(store.snapshot())

def test_timestamps(store,detector):
    s=Synthetic();Pipeline(store,detector,[s]).scan(s,"demo")
    a=store.snapshot()["alerts"][0]
    assert a["published_at"]<=a["first_seen_at"]<=a["scanned_at"]<=a["alerted_at"]
    assert a["collection_delay_ms"]>=0 and a["alert_delay_ms"]>=0

def test_error_sanitization_and_checkpoint(store,detector):
    class Broken(Synthetic):
        def fetch(self,*args):
            raise RuntimeError(samples()[0][1])
    s=Broken();r=Pipeline(store,detector,[s]).scan(s)
    assert r["error_code"]=="scan_failed"
    assert store.checkpoint(s.source_id)==(None,None)
    assert samples()[0][1] not in json.dumps(store.snapshot())

def test_atomic_rollback(store,detector):
    class Broken(Synthetic):
        def fetch(self,*args):
            return Batch([Document("ok",samples()[0][1]),Document("fail",None)],"new")
    s=Broken();r=Pipeline(store,detector,[s]).scan(s)
    assert r["status"]=="error"
    assert not store.snapshot()["alerts"]
    assert store.checkpoint(s.source_id)==(None,None)

def test_untrusted_metadata_is_opaque(store,detector):
    raw=samples()[0][1]
    class Meta(Synthetic):
        def fetch(self,*args):
            return Batch([Document(raw,raw,raw)],"v1")
    s=Meta();Pipeline(store,detector,[s]).scan(s)
    assert raw not in json.dumps(store.snapshot())

def test_no_publication_means_unavailable(store,detector):
    class Undated(Synthetic):
        def fetch(self,*args):
            return Batch([Document("test",samples()[0][1])],"v1")
    s=Undated();Pipeline(store,detector,[s]).scan(s)
    a=store.snapshot()["alerts"][0]
    assert a["published_at"] is None and a["collection_delay_ms"] is None

def test_invalid_publication_metadata_is_not_persisted(store,detector):
    raw=samples()[0][1]
    class Meta(Synthetic):
        def fetch(self,*args):
            return Batch([Document("safe",raw,"safe",raw)],"v2")
    s=Meta();Pipeline(store,detector,[s]).scan(s)
    assert raw not in json.dumps(store.snapshot())
    assert store.snapshot()["alerts"][0]["published_at"] is None

def test_different_key_rejected(store,detector):
    from secretradar.detectors.rules import Detector
    s=Synthetic();Pipeline(store,detector,[s]).scan(s)
    with pytest.raises(SourceError,match="hmac_key_mismatch"):
        Pipeline(store,Detector(b"ANOTHER_TEST_ONLY_KEY_0000000000000000"),[s])

def test_malicious_etag_discarded(store,detector):
    raw=samples()[0][1]
    class Tagged(Synthetic):
        def fetch(self,*args):
            return Batch([], "v1", raw)
    s=Tagged();Pipeline(store,detector,[s]).scan(s)
    assert store.checkpoint(s.source_id)[1] is None

def test_checkpoint_rejects_punctuated_payload(store,detector):
    class BadCursor(Synthetic):
        def fetch(self,*args):
            return Batch([],samples()[0][1])
    s=BadCursor();r=Pipeline(store,detector,[s]).scan(s)
    assert r["status"]=="error" and r["error_code"]=="unsafe_checkpoint"

def test_sqlite_handles_close_on_windows(store,detector):
    from pathlib import Path
    s=Synthetic();Pipeline(store,detector,[s]).scan(s,"demo")
    store.snapshot()
    Path(store.path).unlink()
    assert not Path(store.path).exists()
