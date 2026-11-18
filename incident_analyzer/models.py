"""Shared in-memory ingestion models. No evidence is written to disk."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class InputFile:
    filename: str
    content: bytes


@dataclass
class FileImport:
    import_id: str
    filename: str
    byte_count: int
    sha256: str
    imported_at: datetime
    assumed_timezone: str | None
    original_bytes: bytes = field(default=b"", repr=False)
    input_records: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    new_events: int = 0
    file_error: str | None = None


@dataclass(frozen=True)
class SourceOccurrence:
    occurrence_id: str
    source_ref: str
    import_id: str
    filename: str
    file_sha256: str
    record_position: int
    line_start: int
    line_end: int
    original_fields: dict[str, Any]
    source_record: str
    original_timestamp: str
    original_offset: str | None
    assumed_timezone: str | None
    resolved_offset: str


@dataclass(frozen=True)
class ValidationIssue:
    import_id: str
    filename: str
    source_ref: str
    record_position: int
    line_start: int
    line_end: int
    message: str
    source_record: str
    original_fields: Any = None


@dataclass
class NormalizedEvent:
    event_key: str
    timestamp_utc: datetime
    fields: dict[str, Any]
    occurrences: list[SourceOccurrence] = field(default_factory=list)

    @property
    def duplicate_count(self) -> int:
        return max(0, len(self.occurrences) - 1)


@dataclass(frozen=True)
class ParsedRecord:
    position: int
    line_start: int
    line_end: int
    raw: str
    fields: Any
    error: str | None = None
    original_fields: Any = None
