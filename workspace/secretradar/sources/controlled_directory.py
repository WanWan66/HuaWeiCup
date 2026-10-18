"""Explicit synthetic-directory I/O benchmark adapter; not an extra public channel."""
import hashlib
import hmac
import os
from pathlib import Path
from ..model import Batch,Document,SourceError
from .local import MAX_FILE,MAX_TOTAL
class ControlledDirectory:
    source_type="controlled_directory"
    def __init__(self,source_id,scope):
        self.source_id,self.scope=source_id,str(Path(scope).resolve())
    def fetch(self,since=None,etag=None):
        root=Path(self.scope)
        marker=root/".secretradar-synthetic-fixture"
        if marker.read_text()!="SYNTHETIC_ONLY":raise SourceError("synthetic_fixture_marker_required")
        files=sorted(root.glob("*.txt"))
        if len(files)>10000:raise SourceError("controlled_file_limit")
        key=os.environ.get("SECRETRADAR_HMAC_KEY","").encode()
        if len(key)<32:raise SourceError("hmac_key_missing")
        checksum=hmac.new(key,digestmod=hashlib.sha256);docs=[];total=0
        for path in files:
            if path.is_symlink() or not path.resolve().is_relative_to(root):raise SourceError("controlled_symlink_denied")
            raw=path.read_bytes();total+=len(raw)
            if len(raw)>MAX_FILE or total>MAX_TOTAL:raise SourceError("controlled_content_limit")
            checksum.update(path.name.encode()+b"\0"+raw+b"\0")
            docs.append(Document(path.name,raw.decode("utf-8"),"synthetic-file",None,True))
        cursor=checksum.hexdigest()
        return Batch([] if cursor==since else docs,cursor,unchanged=cursor==since)
