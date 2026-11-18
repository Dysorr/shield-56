"""Session-only, bounded, transactional evidence imports and distinct-event access."""

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256

from incident_analyzer.models import (
    FileImport, InputFile, NormalizedEvent, SourceOccurrence, ValidationIssue,
)
from incident_analyzer.normalization import normalize_record
from incident_analyzer.parsing import FileReadError, parse_records
from incident_analyzer.schema import EventValidationError, decode_csv_record

MAX_FILE_BYTES = 10_000_000
MAX_SESSION_BYTES = 20_000_000
MAX_INPUT_RECORDS = 50_000


class ImportLimitError(ValueError):
    """The entire proposed batch was rejected without changing the session."""


class ImportSession:
    def __init__(self):
        self.files: list[FileImport] = []
        self.events: dict[str, NormalizedEvent] = {}
        self.errors: list[ValidationIssue] = []
        self.total_bytes = 0
        self.total_records = 0

    @property
    def analysis_events(self):
        """The only detection input: each complete normalized event exactly once."""
        return tuple(sorted(self.events.values(), key=lambda event: (event.timestamp_utc, event.event_key)))

    def import_files(self, files: list[InputFile], assumed_timezone=None):
        if any(not isinstance(file.content, bytes) for file in files):
            raise TypeError("InputFile.content must contain the original bytes")
        if any(len(file.content) > MAX_FILE_BYTES for file in files):
            raise ImportLimitError("10 MB (10,000,000 bytes) per-file limit exceeded; batch not imported")
        byte_count = sum(len(file.content) for file in files)
        if self.total_bytes + byte_count > MAX_SESSION_BYTES:
            raise ImportLimitError("20 MB (20,000,000 bytes) session limit exceeded; batch not imported")
        staged_files, staged_errors, staged_events = [], [], []
        record_count = 0
        now = datetime.now(timezone.utc)
        for number, file in enumerate(files, len(self.files) + 1):
            # Exact byte hash happens before decoding/parsing any record in this file.
            metadata = FileImport(
                import_id=f"import_{number}", filename=file.filename,
                byte_count=len(file.content), sha256=sha256(file.content).hexdigest(),
                imported_at=now, assumed_timezone=assumed_timezone,
                original_bytes=file.content,
            )
            file_events, file_errors = [], []
            try:
                for record in parse_records(file.filename, file.content):
                    record_count += 1
                    if self.total_records + record_count > MAX_INPUT_RECORDS:
                        raise ImportLimitError(
                            "50,000 cumulative input-record limit exceeded; batch not imported"
                        )
                    metadata.input_records += 1
                    source_ref = f"{metadata.sha256}:record:{record.position}"
                    try:
                        if record.error:
                            raise EventValidationError(record.error)
                        fields = record.fields
                        if file.filename.lower().endswith(".csv"):
                            fields = decode_csv_record(fields)
                        key, utc, canonical, offset, assumption, resolved = normalize_record(
                            fields, assumed_timezone,
                        )
                        occurrence = SourceOccurrence(
                            occurrence_id=f"{metadata.import_id}:record:{record.position}",
                            source_ref=source_ref, import_id=metadata.import_id,
                            filename=file.filename, file_sha256=metadata.sha256,
                            record_position=record.position, line_start=record.line_start,
                            line_end=record.line_end, original_fields=deepcopy(
                                record.original_fields if record.original_fields is not None else record.fields),
                            source_record=record.raw, original_timestamp=record.fields["timestamp"],
                            original_offset=offset, assumed_timezone=assumption,
                            resolved_offset=resolved,
                        )
                        file_events.append((metadata, key, utc, canonical, occurrence))
                        metadata.accepted += 1
                    except (EventValidationError, TypeError, OverflowError, RecursionError) as error:
                        metadata.rejected += 1
                        file_errors.append(ValidationIssue(
                            metadata.import_id, file.filename, source_ref, record.position,
                            record.line_start, record.line_end, str(error), record.raw,
                            deepcopy(record.original_fields if record.original_fields is not None else record.fields),
                        ))
            except FileReadError as error:
                metadata.file_error = str(error)
            staged_files.append(metadata)
            staged_events.extend(file_events)
            staged_errors.extend(file_errors)
        # Commit only once all session limits have passed, including rejected rows.
        for metadata, key, utc, canonical, occurrence in staged_events:
            if key in self.events:
                metadata.duplicates += 1
            else:
                self.events[key] = NormalizedEvent(key, utc, canonical)
                metadata.new_events += 1
            self.events[key].occurrences.append(occurrence)
        self.files.extend(staged_files)
        self.errors.extend(staged_errors)
        self.total_bytes += byte_count
        self.total_records += record_count
        return staged_files
