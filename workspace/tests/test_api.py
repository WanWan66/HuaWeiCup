import json
import threading
import time
import urllib.error
import urllib.request
import uvicorn
from secretradar.api.app import create_app
from secretradar.evaluation.fixtures import Synthetic,samples
from secretradar.pipeline.scan import Pipeline

def test_actual_loopback_http(store,detector):
    s=Synthetic();Pipeline(store,detector,[s]).scan(s,"demo")
    import socket
    sock=socket.socket();sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(create_app(store,"demo"),log_level="critical",access_log=False))
    thread=threading.Thread(target=server.run,kwargs={"sockets":[sock]},daemon=True);thread.start()
    try:
        for _ in range(100):
            if server.started:break
            time.sleep(0.02)
        assert server.started
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/dashboard",timeout=5) as response:
            body=response.read().decode()
        assert json.loads(body)["metrics"]["alerts"]==7
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/",timeout=5) as response:
            page=response.read().decode()
        assert "DEMO" in page and "[REDACTED]" in page and "{{" not in page
        assert samples()[0][1].split("=")[1] not in body+page
    finally:
        server.should_exit=True;thread.join(5);sock.close()
    assert not thread.is_alive()

def test_mode_comes_from_recorded_jobs(store,detector):
    s=Synthetic();Pipeline(store,detector,[s]).scan(s,"demo")
    app=create_app(store,"real")
    route=next(r for r in app.routes if r.path=="/health")
    assert route.endpoint()["mode"]=="demo"
