"""Actual loopback HTTP protocol fixtures. All documents are explicitly synthetic."""
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import threading
import time
from urllib.parse import urlsplit
from ..model import now
from .fixtures import samples
class ControlledServer:
    def __init__(self):
        self.lock=threading.Lock();self.documents=[];self.version=0;self.github_stage=0;self.requests=0
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                path=urlsplit(self.path).path
                if path=="/slow":time.sleep(2)
                with owner.lock:
                    owner.requests+=1;docs=list(owner.documents);version=owner.version;stage=owner.github_stage
                if path in {"/feed","/slow"}:
                    data={"version":version,"documents":docs}
                elif path=="/wiki/api.php":
                    data={"query":{"pages":[{"pageid":x["id"],"title":x["path"],"revisions":[{"revid":x["id"],"slots":{"main":{"content":x["text"]}}}]} for x in docs]}}
                elif path.endswith("/commits"):
                    data=[{"sha":("a" if stage==0 else "c")*40}]
                elif "/compare/" in path:
                    data={"status":"ahead","total_commits":2,"commits":[{"sha":"b"*40},{"sha":"c"*40}]}
                elif "/git/trees/" in path:
                    revision=path.rsplit("/",1)[1]
                    data={"truncated":False,"tree":([{"type":"blob","path":"unit.txt","sha":"d"*40,"size":100}] if revision=="b"*40 else [])}
                elif "/git/blobs/" in path:
                    data={"encoding":"base64","content":base64.b64encode(samples()[0][1].encode()).decode()}
                else:
                    self.send_response(404);self.end_headers();return
                body=json.dumps(data).encode()
                self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)));self.end_headers()
                try:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Handler);self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.base="http://127.0.0.1:"+str(self.server.server_port)
    def __enter__(self):
        self.thread.start();return self
    def __exit__(self,*args):
        self.server.shutdown();self.server.server_close();self.thread.join(3)
    def publish(self,text,created_at=None):
        created_at=created_at or now()
        with self.lock:
            self.version+=1
            item={"id":self.version,"path":"synthetic-"+str(self.version)+".txt","text":text,
                  "created_at":created_at,"accessible_at":now()}
            self.documents.append(item)
        return {"id":item["id"],"created_at":created_at,"accessible_at":item["accessible_at"]}
