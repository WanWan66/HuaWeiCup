import io
import json
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from ..model import Batch, Document, SourceError

MAX_FILE = 1024 * 1024
MAX_TOTAL = 16 * MAX_FILE
MAX_DOCS = 500
MAX_COMMITS = 200

def git(path, *args):
    try:
        run = subprocess.run(["git", "-C", str(path), *args], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise SourceError("git_unavailable") from None
    if run.returncode:
        raise SourceError("git_command_failed")
    if len(run.stdout) > MAX_TOTAL:
        raise SourceError("git_output_limit")
    return run.stdout

class LocalGit:
    source_type = "local_git"
    def __init__(self, source_id, scope):
        self.source_id, self.scope = source_id, str(Path(scope).resolve())

    def fetch(self, since=None, etag=None):
        root = git(self.scope, "rev-parse", "--show-toplevel").decode().strip()
        if Path(root).resolve() != Path(self.scope).resolve():
            raise SourceError("scope_not_repository_root")
        head = git(self.scope, "rev-parse", "HEAD").decode().strip()
        if head == since:
            return Batch([], head, unchanged=True)
        revision = head
        if since:
            try:
                git(self.scope, "merge-base", "--is-ancestor", since, head)
                revision = since + ".." + head
            except SourceError:
                pass  # Rewritten history: bounded full history rescan.
        commits = git(self.scope, "rev-list", "--reverse", "--max-count=" + str(MAX_COMMITS+1), revision).decode().splitlines()
        if len(commits) > MAX_COMMITS:
            raise SourceError("history_limit_requires_review")
        docs, total = [], 0
        for commit in commits:
            changes = git(self.scope, "diff-tree", "--root", "--no-commit-id", "--name-status",
                          "--diff-merges=first-parent", "--no-renames", "-r", "-z", commit).split(b"\0")
            for index in range(0, len(changes)-1, 2):
                status, raw_name = changes[index:index+2]
                if status == b"D":
                    continue
                name = raw_name.decode("utf-8", "replace")
                data = git(self.scope, "show", commit + ":" + name)
                total += len(data)
                if len(data) > MAX_FILE or total > MAX_TOTAL or len(docs) >= MAX_DOCS:
                    raise SourceError("document_limit")
                if b"\0" not in data:
                    # Commit time is not reliable public release time.
                    docs.append(Document(name, data.decode("utf-8", "replace"), commit))
        return Batch(docs, head)

class OCIArchive:
    source_type = "oci_archive"
    def __init__(self, source_id, scope):
        self.source_id, self.scope = source_id, str(Path(scope).resolve())

    def fetch(self, since=None, etag=None):
        # Read only the nominated archive. Never extract layer paths to disk.
        archive_path = Path(self.scope)
        if archive_path.stat().st_size > MAX_TOTAL:
            raise SourceError("archive_size_limit")
        import hashlib
        data = archive_path.read_bytes()
        cursor = hashlib.sha256(data).hexdigest()  # Archive identity, not a credential fingerprint.
        if since == cursor:
            return Batch([], cursor, unchanged=True)
        docs, budget = [], 0
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                index_file = archive.extractfile("index.json")
                if not index_file:
                    raise SourceError("oci_index_missing")
                index = json.loads(index_file.read(MAX_FILE+1))
                if len(index["manifests"]) > 10:
                    raise SourceError("oci_manifest_limit")
                for desc in index["manifests"]:
                    digest = desc["digest"]
                    manifest = self._blob(archive, digest)
                    layers = json.loads(manifest)["layers"]
                    if len(layers) > 50:
                        raise SourceError("oci_layer_limit")
                    for layer in layers:
                        layer_bytes = self._blob(archive, layer["digest"])
                        with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer_tar:
                            for member in layer_tar:
                                if not member.isfile():
                                    continue
                                parts = PurePosixPath(member.name)
                                if parts.is_absolute() or ".." in parts.parts or "\\" in member.name:
                                    raise SourceError("unsafe_archive_path")
                                budget += member.size
                                if member.size > MAX_FILE or budget > MAX_TOTAL or len(docs) >= MAX_DOCS:
                                    raise SourceError("archive_content_limit")
                                content = layer_tar.extractfile(member).read(MAX_FILE+1)
                                if b"\0" not in content:
                                    docs.append(Document(member.name, content.decode("utf-8", "replace"), layer["digest"]))
        except SourceError:
            raise
        except Exception:
            raise SourceError("oci_invalid") from None
        # Historical-layer scan includes files removed by whiteouts, as leaked content persists in blobs.
        return Batch(docs, cursor)

    @staticmethod
    def _blob(archive, digest):
        import hashlib
        if not isinstance(digest, str) or not __import__("re").fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise SourceError("oci_digest_invalid")
        f = archive.extractfile("blobs/sha256/" + digest.split(":")[1])
        if not f:
            raise SourceError("oci_blob_missing")
        content = f.read(MAX_TOTAL + 1)
        if len(content) > MAX_TOTAL:
            raise SourceError("oci_blob_limit")
        if hashlib.sha256(content).hexdigest() != digest.split(":")[1]:
            raise SourceError("oci_digest_mismatch")
        return content
