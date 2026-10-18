import base64
import io
import json
import urllib.error
import pytest
from secretradar.evaluation.fixtures import git_repo,oci_archive,samples
from secretradar.model import SourceError
from secretradar.pipeline.scan import Pipeline
from secretradar.sources.local import LocalGit,OCIArchive
from secretradar.sources.remote import GitHub,MediaWiki,HTTP
from secretradar.sources.registry import configured

def test_local_git_real_commands(tmp_path,store,detector):
    path=tmp_path/"controlled";command=git_repo(path)
    s=LocalGit("local_test",path);p=Pipeline(store,detector,[s])
    a=p.scan(s);b=p.scan(s)
    assert a["new_alerts"]==1 and b["documents"]==0
    (path/"new.txt").write_text(samples()[1][1],encoding="utf-8")
    command("add",".");command("commit","-q","-m","Synthetic increment")
    c=p.scan(s)
    assert c["documents"]==1 and c["new_alerts"]==1
    assert store.snapshot()["alerts"][0]["published_at"] is None

def test_local_git_bad_path(tmp_path):
    with pytest.raises(SourceError):
        LocalGit("bad",tmp_path).fetch()

def test_oci_real_archive(tmp_path,store,detector):
    path=tmp_path/"controlled.tar";oci_archive(path)
    s=OCIArchive("oci_test",path);p=Pipeline(store,detector,[s])
    assert p.scan(s)["new_alerts"]==1
    assert p.scan(s)["documents"]==0

def test_oci_path_traversal(tmp_path):
    path=tmp_path/"bad.tar";oci_archive(path,True)
    with pytest.raises(SourceError,match="unsafe_archive_path"):
        OCIArchive("oci_test",path).fetch()
    assert not (tmp_path/"escape").exists()

def test_empty_allowlist(tmp_path):
    f=tmp_path/"config.json";f.write_text('{"allowed_sources":[]}')
    assert configured(f)==[]

def test_invalid_source_id(tmp_path):
    f=tmp_path/"config.json"
    f.write_text(json.dumps({"allowed_sources":[{"source_id":"bad/token","source_type":"local_git","scope":"."}]}))
    with pytest.raises(SourceError):
        configured(f)

def test_github_adapter_mock():
    class MockHTTP:
        def get(self,url,etag=None):
            if "/commits?" in url:
                return ([{"sha":"a"*40}],"test-etag",False)
            if "/trees/" in url:
                return ({"tree":[{"type":"blob","path":"x","sha":"b"*40,"size":80}]},None,False)
            return ({"content":base64.b64encode(samples()[0][1].encode()).decode()},None,False)
    batch=GitHub("github_test","controlled/repo",MockHTTP()).fetch()
    assert len(batch.documents)==1 and batch.documents[0].published_at is None

def test_github_no_redirect_scope():
    with pytest.raises(SourceError):
        GitHub("bad","https://foreign.invalid/repo")

def test_wiki_adapter_mock():
    class MockHTTP:
        def get(self,url,etag=None):
            return ({"query":{"pages":[{"pageid":1,"title":"Controlled","revisions":[{"slots":{"main":{"content":samples()[0][1]}}}]}]}},None,False)
    s=MediaWiki("wiki_test","https://controlled.invalid/api.php",MockHTTP())
    first=s.fetch()
    assert len(first.documents)==1
    assert s.fetch(first.cursor).unchanged

def test_wiki_requires_https():
    with pytest.raises(SourceError):
        MediaWiki("bad","http://controlled.invalid/api.php")

class Response:
    headers={"ETag":'"'+"a"*40+'"'}
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,size):return b'{"ok":true}'

def test_http_etag_304():
    class Opener:
        def open(self,request,timeout):
            assert request.get_header("If-none-match")=='"tag"'
            raise urllib.error.HTTPError(request.full_url,304,"Not modified",{},None)
    assert HTTP(Opener()).get("https://controlled.invalid",'"tag"')[2]

def test_rate_limit_backoff():
    calls=[];sleeps=[]
    class Opener:
        def open(self,request,timeout):
            calls.append(1)
            if len(calls)<3:
                raise urllib.error.HTTPError(request.full_url,429,"Limited",{"Retry-After":"1"},None)
            return Response()
    assert HTTP(Opener(),sleeps.append).get("https://controlled.invalid")[0]["ok"]
    assert sleeps==[1,2] and len(calls)==3

def test_rate_limit_long_retry_deferred():
    class Opener:
        def open(self,request,timeout):
            raise urllib.error.HTTPError(request.full_url,429,"Limited",{"Retry-After":"120"},None)
    with pytest.raises(SourceError,match="rate_limited_deferred"):
        HTTP(Opener(),lambda _:None).get("https://controlled.invalid")

def test_network_errors_are_sanitized():
    class Opener:
        def open(self,*args,**kwargs):
            raise OSError(samples()[0][1])
    with pytest.raises(SourceError,match="http_transport_failure") as e:
        HTTP(Opener(),lambda _:None).get("https://controlled.invalid")
    assert samples()[0][1] not in str(e.value)

def test_git_nested_directory_scope_not_ancestor(tmp_path):
    path=tmp_path/"controlled";git_repo(path)
    nested=path/"nested";nested.mkdir()
    with pytest.raises(SourceError,match="scope_not_repository_root"):
        LocalGit("local_test",nested).fetch()

def test_git_deleted_file_and_history(tmp_path,store,detector):
    path=tmp_path/"controlled";command=git_repo(path)
    (path/"controlled.txt").unlink()
    command("add","-A");command("commit","-q","-m","Delete controlled synthetic data")
    s=LocalGit("local_test",path);p=Pipeline(store,detector,[s])
    assert p.scan(s)["new_alerts"]==1
    assert p.scan(s)["documents"]==0
