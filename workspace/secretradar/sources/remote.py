import base64
import json
import time
import os
import math
import math
import re
from email.utils import parsedate_to_datetime
import urllib.error
import urllib.parse
import urllib.request
from ..model import Batch, Document, SourceError
from .local import MAX_FILE, MAX_TOTAL, MAX_DOCS

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

class HTTP:
    def __init__(self, opener=None, sleep=time.sleep):
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.sleep = sleep

    def get(self, url, etag=None):
        headers = {"Accept": "application/json", "User-Agent": "SecretRadar-authorized-review/0.2"}
        if urllib.parse.urlsplit(url).hostname == "api.github.com" and os.environ.get("SECRETRADAR_GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["SECRETRADAR_GITHUB_TOKEN"]
        if etag:
            headers["If-None-Match"] = etag
        for attempt in range(3):
            try:
                with self.opener.open(urllib.request.Request(url, headers=headers), timeout=10) as r:
                    body = r.read(MAX_TOTAL+1)
                    if len(body) > MAX_TOTAL:
                        raise SourceError("http_body_limit")
                    return json.loads(body), r.headers.get("ETag"), False
            except urllib.error.HTTPError as e:
                if e.code == 304:
                    return None, etag, True
                proxy = e.headers.get("X-Mitmproxy-Blocked-Reason")
                if proxy:raise SourceError("proxy_rejected") from None
                limited = e.code == 429 or (e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0")
                service_error = e.code in (500,502,503,504)
                if limited or service_error:
                    try:
                        header=e.headers.get("Retry-After")
                        if header:
                            try:retry=float(header)
                            except ValueError:retry=max(0,parsedate_to_datetime(header).timestamp()-time.time())
                        elif limited and e.headers.get("X-RateLimit-Reset"):
                            retry=max(0,float(e.headers["X-RateLimit-Reset"])-time.time()+1)
                        else:retry=float(2**attempt)
                        if not math.isfinite(retry) or retry>8 or retry<0:
                            raise SourceError("rate_limited_deferred" if limited else "service_retry_deferred",retry_after=retry)
                    except (TypeError,ValueError,OverflowError):
                        raise SourceError("rate_limited_deferred" if limited else "service_retry_deferred") from None
                    if attempt<2:
                        self.sleep(max(retry,2**attempt));continue
                    raise SourceError("rate_limited" if limited else "platform_service_error",retry_after=retry) from None
                code={401:"authentication_required",404:"not_found_or_not_authorized",422:"request_parameters_invalid"}.get(e.code,"http_"+str(e.code))
                raise SourceError(code) from None
            except SourceError:
                raise
            except (OSError, ValueError):
                if attempt == 2:
                    raise SourceError("http_transport_failure") from None
                self.sleep(2 ** attempt)
        raise SourceError("http_retry_exhausted")

class GitHub:
    source_type = "github"
    def __init__(self, source_id, scope, http=None, api_base=None):
        import re
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", scope):
            raise SourceError("github_scope_invalid")
        self.source_id, self.scope = source_id, scope
        self.http = http or HTTP()
        self.api_base=api_base or "https://api.github.com"
        parsed=urllib.parse.urlsplit(self.api_base)
        if api_base and not (parsed.scheme=="http" and parsed.hostname in {"127.0.0.1","::1"} and not parsed.username and not parsed.query and not parsed.fragment):
            raise SourceError("custom_api_only_controlled_loopback")
        if any(part in {".",".."} for part in scope.split("/")):raise SourceError("github_scope_invalid")

    def fetch(self, since=None, etag=None):
        api = self.api_base.rstrip("/") + "/repos/" + self.scope
        commits, tag, unchanged = self.http.get(api + "/commits?per_page=1", etag)
        if unchanged:
            return Batch([], since, tag, unchanged=True)
        if not commits:
            raise SourceError("github_empty_repository")
        head = commits[0]["sha"]
        if not __import__("re").fullmatch(r"[a-f0-9]{40,64}", head):
            raise SourceError("github_revision_invalid")
        if head == since:
            return Batch([], head, tag, unchanged=True)
        revisions=[head]
        if since:
            comparison,_,_=self.http.get(api+"/compare/"+since+"..."+head+"?per_page=100")
            if comparison.get("status") not in {"ahead","identical"}:
                raise SourceError("github_history_rewritten_requires_full")
            revisions=[item["sha"] for item in comparison.get("commits",[])]
            if len(revisions)!=comparison.get("total_commits") or len(revisions)>100:
                raise SourceError("github_commit_backlog_limit")
        prior={}
        if since:
            old,_,_=self.http.get(api+"/git/trees/"+since+"?recursive=1")
            if old.get("truncated"):raise SourceError("github_tree_truncated")
            prior={x["path"]:x["sha"] for x in old["tree"] if x["type"]=="blob"}
        docs=[];budget=0;requests=0
        for revision in revisions:
            if not re.fullmatch(r"[a-f0-9]{40,64}",revision):raise SourceError("github_revision_invalid")
            tree,_,_=self.http.get(api+"/git/trees/"+revision+"?recursive=1")
            if tree.get("truncated"):raise SourceError("github_tree_truncated")
            current={}
            for entry in tree["tree"]:
                if entry["type"]!="blob":continue
                current[entry["path"]]=entry["sha"]
                if prior.get(entry["path"])==entry["sha"]:continue
                if entry.get("size",MAX_FILE+1)>MAX_FILE or len(docs)>=MAX_DOCS or requests>=200:
                    raise SourceError("github_document_limit")
                if not re.fullmatch(r"[a-f0-9]{40,64}",entry["sha"]):raise SourceError("github_blob_id_invalid")
                blob,_,_=self.http.get(api+"/git/blobs/"+entry["sha"]);requests+=1
                if blob.get("encoding","base64")!="base64":raise SourceError("github_encoding_unsupported")
                content=base64.b64decode(blob["content"],validate=False);budget+=len(content)
                if len(content)>MAX_FILE or budget>MAX_TOTAL:raise SourceError("github_content_limit")
                if b"\0" not in content:
                    docs.append(Document(entry["path"],content.decode("utf-8","replace"),revision))
            prior=current
        return Batch(docs,head,tag)

class MediaWiki:
    source_type = "mediawiki"
    def __init__(self, source_id, scope, http=None, local_protocol=False):
        parsed = urllib.parse.urlsplit(scope)
        permitted = parsed.scheme=="https" or (local_protocol and parsed.scheme=="http" and parsed.hostname in {"127.0.0.1","::1"})
        if not permitted or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise SourceError("wiki_scope_invalid")
        self.source_id, self.scope, self.http = source_id, scope, http or HTTP()

    def fetch(self, since=None, etag=None):
        # Only current main-namespace pages: bounded complete snapshot with continuation.
        base = {"action":"query", "generator":"allpages", "gapnamespace":"0",
                "gaplimit":"50", "prop":"revisions", "rvprop":"content",
                "rvslots":"main", "format":"json", "formatversion":"2"}
        docs, continuation, budget = [], {}, 0
        import hashlib
        hasher = hashlib.sha256()
        for _ in range(10):
            result, _, _ = self.http.get(self.scope + "?" + urllib.parse.urlencode(base | continuation))
            if "error" in result:
                raise SourceError("wiki_api_error")
            for page in result.get("query", {}).get("pages", []):
                text = page["revisions"][0]["slots"]["main"]["content"]
                budget += len(text.encode("utf-8"))
                if budget > MAX_TOTAL or len(docs) >= MAX_DOCS:
                    raise SourceError("wiki_document_limit")
                hasher.update(str(page["pageid"]).encode())
                hasher.update(text.encode())
                docs.append(Document(page["title"], text, "pageid:" + str(page["pageid"])))
            if "continue" not in result:
                cursor = hasher.hexdigest()
                return Batch([] if cursor == since else docs, cursor, unchanged=cursor == since)
            continuation = result["continue"]
        raise SourceError("wiki_page_limit")
