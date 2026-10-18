import json
import re
from pathlib import Path
from ..model import SourceError
from .local import LocalGit, OCIArchive
from .remote import GitHub, MediaWiki

from .controlled import ControlledHTTP

from .controlled_directory import ControlledDirectory

TYPES = {"controlled_directory": ControlledDirectory,"controlled_http": ControlledHTTP,"local_git": LocalGit, "oci_archive": OCIArchive, "github": GitHub, "mediawiki": MediaWiki}

def configured(path):
    try:
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        raise SourceError("config_invalid") from None
    sources, seen = [], set()
    for spec in config.get("allowed_sources", []):
        name = spec.get("source_id", "")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", name) or name in seen:
            raise SourceError("source_id_invalid")
        seen.add(name)
        cls = TYPES.get(spec.get("source_type"))
        if cls is None or not isinstance(spec.get("scope"), str):
            raise SourceError("source_type_or_scope_invalid")
        options={}
        if cls is GitHub and spec.get("api_base"):options["api_base"]=spec["api_base"]
        if cls is MediaWiki and spec.get("local_protocol"):options["local_protocol"]=True
        sources.append(cls(name, spec["scope"],**options))
    return sources
