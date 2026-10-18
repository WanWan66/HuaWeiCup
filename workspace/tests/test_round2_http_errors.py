import urllib.error
import time
import pytest
from secretradar.model import SourceError
from secretradar.sources.remote import HTTP
class Opener:
    def __init__(self,code,headers):self.code=code;self.headers=headers;self.calls=0
    def open(self,request,timeout):
        self.calls+=1
        raise urllib.error.HTTPError(request.full_url,self.code,"never expose upstream text",self.headers,None)
@pytest.mark.parametrize("code,headers,expected",[
    (403,{"X-Mitmproxy-Blocked-Reason":"ROBOTS_DENIED"},"proxy_rejected"),
    (401,{},"authentication_required"),(404,{},"not_found_or_not_authorized"),
    (422,{},"request_parameters_invalid"),(403,{},"http_403")])
def test_distinct_error_categories(code,headers,expected):
    with pytest.raises(SourceError) as error:HTTP(Opener(code,headers),lambda _:None).get("https://api.github.com/repos/unit/owned")
    assert error.value.code==expected
def test_rate_reset_is_respected_without_repeated_requests():
    opener=Opener(403,{"X-RateLimit-Remaining":"0","X-RateLimit-Reset":str(time.time()+600)})
    with pytest.raises(SourceError) as error:HTTP(opener,lambda _:None).get("https://api.github.com/repos/unit/owned")
    assert error.value.code=="rate_limited_deferred" and error.value.retry_after>590 and opener.calls==1
def test_platform_503_is_not_labeled_rate_limit():
    opener=Opener(503,{})
    with pytest.raises(SourceError) as error:HTTP(opener,lambda _:None).get("https://api.github.com/repos/unit/owned")
    assert error.value.code=="platform_service_error" and opener.calls==3
def test_token_never_sent_to_controlled_host(monkeypatch):
    monkeypatch.setenv("SECRETRADAR_GITHUB_TOKEN","TEST_ONLY_NOT_A_REAL_GITHUB_TOKEN")
    class NoToken:
        def open(self,request,timeout):
            assert request.get_header("Authorization") is None
            raise urllib.error.HTTPError(request.full_url,304,"not modified",{},None)
    assert HTTP(NoToken()).get("http://127.0.0.1:9999/")[2]
