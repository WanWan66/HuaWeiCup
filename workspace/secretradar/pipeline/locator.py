"""Operator-only, in-memory file location. Never return paths in public API or logs."""
from pathlib import Path
import subprocess
from ..model import SourceError
from ..sources.local import git
def locate(source,detector,path_id,open_editor=False):
    if source.source_type!="local_git":raise SourceError("locator_only_local_git")
    root=Path(source.scope).resolve()
    for raw in git(root,"ls-files","-z").split(b"\0"):
        if not raw:continue
        name=raw.decode("utf-8","replace")
        if detector.fingerprint(name)!=path_id:continue
        target=(root/name).resolve()
        if not target.is_relative_to(root) or not target.is_file():raise SourceError("locator_path_unavailable")
        if open_editor:
            # Fixed editor, argument array, never execute the nominated file.
            subprocess.Popen(["notepad.exe",str(target)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return target
    raise SourceError("locator_path_unavailable")
