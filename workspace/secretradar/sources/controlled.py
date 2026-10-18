"""Explicit loopback-only controlled protocol source. Never enabled by default."""
from urllib.parse import urlsplit
from ..model import Batch,Document,SourceError
from .remote import HTTP
from .local import MAX_DOCS,MAX_TOTAL
class ControlledHTTP:
    source_type="controlled_http"
    def __init__(self,source_id,scope):
        parsed=urlsplit(scope)
        if parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","::1"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise SourceError("controlled_source_must_be_loopback")
        self.source_id,self.scope=source_id,scope;self.http=HTTP()
    def fetch(self,since=None,etag=None):
        data,tag,unchanged=self.http.get(self.scope,etag)
        if unchanged:return Batch([],since,tag,True)
        cursor=str(data["version"])
        if cursor==since:return Batch([],cursor,tag,True)
        docs=[];total=0
        for item in data["documents"]:
            total+=len(item["text"].encode())
            if len(docs)>=MAX_DOCS or total>MAX_TOTAL:raise SourceError("controlled_content_limit")
            docs.append(Document(item["path"],item["text"],"controlled:"+str(item["id"]),None,True,
                                 item.get("created_at"),item.get("accessible_at")))
        return Batch(docs,cursor,tag)
