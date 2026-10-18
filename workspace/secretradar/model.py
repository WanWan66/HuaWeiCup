from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

def now():
    return datetime.now(timezone.utc).isoformat()

@dataclass(frozen=True)
class Document:
    path: str
    text: str = field(repr=False)
    provenance: str = ""
    published_at: str | None = None
    synthetic: bool = False
    created_at: str | None = None
    accessible_at: str | None = None

@dataclass
class Batch:
    documents: list[Document]
    cursor: str | None
    etag: str | None = None
    unchanged: bool = False

class SourceError(Exception):
    """Public error codes only; never propagate upstream content."""
    def __init__(self, code="source_failure", retry_after=None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(code)

class Source(Protocol):
    source_id: str
    source_type: str
    scope: str
    def fetch(self, since: str | None, etag: str | None = None) -> Batch: ...
