"""Full-case metadata export. Original file bytes are not included in the manifest."""

from dataclasses import asdict
import json


def build_manifest(session):
    files = []
    for imported in session.files:
        row = {key: value for key, value in vars(imported).items() if key != "original_bytes"}
        row["imported_at"] = imported.imported_at.isoformat()
        files.append(row)
    return {
        "format_version": "1.0",
        "scope": "Full case: every import, including repeated and failed imports. Timeline filters do not apply.",
        "timestamp_basis": "UTC; assumptions are recorded per file and per source occurrence.",
        "counts": {
            "files": len(session.files), "input_records": session.total_records,
            "accepted_occurrences": sum(item.accepted for item in session.files),
            "rejected_records": sum(item.rejected for item in session.files),
            "duplicate_occurrences": sum(item.duplicates for item in session.files),
            "distinct_events": len(session.events),
        },
        "files": files,
        "events": [
            {
                "event_key": event.event_key,
                "record_id": event.fields["record_id"],
                "timestamp_utc": event.timestamp_utc.isoformat(),
                "sources": [
                    {key: value for key, value in asdict(occ).items()
                     if key not in ("original_fields", "source_record")}
                    for occ in event.occurrences
                ],
            } for event in session.analysis_events
        ],
        "validation_locations": [
            {key: value for key, value in asdict(issue).items()
             if key not in ("original_fields", "source_record")}
            for issue in session.errors
        ],
        "limitations": "A hash supports integrity checking from the time of hashing; "
                      "it does not establish earlier authenticity, completeness, or chain of custody.",
        "evidence_handling": [
            {"operation": "import", "at_utc": f.imported_at.isoformat(),
             "import_id": f.import_id, "sha256": f.sha256, "byte_count": f.byte_count,
             "hash_scope": "Exact original bytes before parsing"}
            for f in session.files
        ],
    }


def manifest_json(session):
    return json.dumps(build_manifest(session), ensure_ascii=False, indent=2)
