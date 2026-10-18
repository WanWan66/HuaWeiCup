"""Entirely synthetic, unusable local test cases. No network validity checks."""
import hashlib
import io
import json
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from ..model import Batch, Document

def samples():
    token = "SRTEST_7xQ2mP9vB4nL6cD8jF3sH5aK"
    return [
        ("api", "api_token=" + token, {"api_token"}),
        ("oauth", "client_secret=SRTEST_9qW3eR8tY2uI6oP4aS7dF5gH", {"oauth_client_secret"}),
        ("db", "postgresql://synthetic:SRTEST_8nJ4pL2cV9xR@localhost/test", {"database_uri"}),
        ("password", "db_password=SRTEST_8vC3xZ6mN2bQ5", {"database_password"}),
        ("ssh", __import__("secretradar.evaluation.round2_dataset",fromlist=["key_block"]).key_block(__import__("random").Random(7)), {"ssh_private_key"}),
        ("cloud_pair", "aws_access_key_id=AKIA7B2D9F4H6J8L3N5P\naws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD", {"cloud_key_pair"}),
        ("entropy", "signing_secret=Q9w2E7r4T8y1U6i3O5p0A2s7D9f4G8h1", {"high_entropy"}),
        ("placeholder_api", "api_token=your_example_api_token_replace_me", set()),
        ("placeholder_oauth", "client_secret=example_client_secret_replace_me", set()),
        ("placeholder_db", "db_password=changeme_placeholder", set()),
        ("low_entropy", "api_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaa", set()),
        ("normal", "Welcome to SecretRadar. This document has no credentials.", set()),
        ("identifier", "ordinary_identifier_with_many_lowercase_letters", set()),
        ("url", "https://localhost/docs/reference", set()),
    ]

class Synthetic:
    source_id = "controlled_demo"
    source_type = "synthetic"
    scope = "memory://controlled-demo"
    def __init__(self, published_at=None):
        self.published_at = published_at or datetime.now(timezone.utc).isoformat()
    def fetch(self, since=None, etag=None):
        if since == "fixture-v1":
            return Batch([], "fixture-v1", unchanged=True)
        return Batch([Document(name+".txt", text, "fixture:"+name, self.published_at, True)
                      for name,text,_ in samples()], "fixture-v1")

def git_repo(path, text=None):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    def command(*args):
        subprocess.run(["git","-C",str(path),*args], check=True, capture_output=True)
    command("init","-q")
    command("config","user.name","SecretRadar synthetic fixture")
    command("config","user.email","synthetic@localhost.invalid")
    (path / "controlled.txt").write_text(text or samples()[0][1], encoding="utf-8")
    command("add",".")
    command("commit","-q","-m","Synthetic fixture; no real credentials")
    return command

def oci_archive(path, malicious=False):
    def tar_bytes(entries):
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode="w") as tar:
            for name,data in entries:
                item=tarfile.TarInfo(name); item.size=len(data)
                tar.addfile(item,io.BytesIO(data))
        return buf.getvalue()
    layer=tar_bytes([("../escape" if malicious else "app/settings.txt",samples()[0][1].encode())])
    layer_sha=hashlib.sha256(layer).hexdigest()
    manifest=json.dumps({"schemaVersion":2,"layers":[{"digest":"sha256:"+layer_sha}]}).encode()
    manifest_sha=hashlib.sha256(manifest).hexdigest()
    index=json.dumps({"schemaVersion":2,"manifests":[{"digest":"sha256:"+manifest_sha}]}).encode()
    Path(path).write_bytes(tar_bytes([("oci-layout",b'{"imageLayoutVersion":"1.0.0"}'),("index.json",index),
        ("blobs/sha256/"+manifest_sha,manifest),("blobs/sha256/"+layer_sha,layer)]))
