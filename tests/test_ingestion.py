"""Exact provenance, shared normalization, deduplication, limits and safe failures."""

from copy import deepcopy
import csv
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from pathlib import Path

import pytest

from incident_analyzer.detection import detection_events
from incident_analyzer.ingestion import (
    ImportLimitError, ImportSession, MAX_FILE_BYTES, MAX_INPUT_RECORDS, MAX_SESSION_BYTES,
)
from incident_analyzer.models import InputFile
from incident_analyzer.schema import EVENT_FIELDS
from scripts.synthetic_scenarios import build_scenarios

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def record():
    return deepcopy(build_scenarios()["suspicious_sequence"][-2])


def json_file(records, name="events.jsonl"):
    return InputFile(name, "".join(json.dumps(row) + "\n" for row in records).encode())


def csv_file(records, name="events.csv"):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=EVENT_FIELDS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(records)
    return InputFile(name, stream.getvalue().encode())


def test_exact_file_hash_bytes_metadata_and_stable_source_reference(record):
    file = json_file([record])
    before = datetime.now(timezone.utc)
    session = ImportSession()
    imported, = session.import_files([file])
    assert imported.sha256 == sha256(file.content).hexdigest()
    assert imported.original_bytes == file.content
    assert imported.byte_count == len(file.content)
    assert imported.filename == file.filename
    assert before <= imported.imported_at <= datetime.now(timezone.utc)
    occurrence, = session.analysis_events[0].occurrences
    assert occurrence.source_ref == f"{imported.sha256}:record:1"
    assert occurrence.source_record.encode() == file.content
    assert occurrence.original_fields == record
    assert occurrence.original_timestamp == record["timestamp"]
    assert occurrence.original_offset == "Z"
    assert occurrence.assumed_timezone is None
    session.import_files([InputFile("renamed.jsonl", file.content)])
    first, second = session.analysis_events[0].occurrences
    assert first.source_ref == second.source_ref
    assert first.occurrence_id != second.occurrence_id
    assert second.filename == "renamed.jsonl"
    assert session.analysis_events[0].duplicate_count == 1


def test_hash_differs_for_only_line_ending_change_but_event_is_duplicate(record):
    file = json_file([record])
    changed = InputFile("crlf.jsonl", file.content.replace(b"\n", b"\r\n"))
    session = ImportSession()
    first, second = session.import_files([file, changed])
    assert first.sha256 != second.sha256
    assert second.duplicates == 1
    assert len(session.analysis_events[0].occurrences) == 2


@pytest.mark.parametrize("scenario", ["normal_activity", "suspicious_sequence", "edge_cases"])
def test_bundled_csv_jsonl_consistency_and_counts(scenario):
    session = ImportSession()
    files = [
        InputFile(path.name, path.read_bytes())
        for extension in ("csv", "jsonl")
        for path in [ROOT / f"data/synthetic/{scenario}.synthetic.{extension}"]
    ]
    csv_import, json_import = session.import_files(files)
    expected_input, expected_accepted, expected_distinct = {
        "normal_activity": (15, 15, 15),
        "suspicious_sequence": (19, 19, 19),
        "edge_cases": (10, 8, 7),
    }[scenario]
    assert csv_import.input_records == json_import.input_records == expected_input
    assert csv_import.accepted == json_import.accepted == expected_accepted
    assert len(session.analysis_events) == expected_distinct
    assert csv_import.duplicates == expected_accepted - expected_distinct
    assert json_import.duplicates == expected_accepted
    assert sum(len(event.occurrences) for event in session.analysis_events) == expected_accepted * 2
    assert len(detection_events(session)) == expected_distinct
    assert sum(file.accepted + file.rejected for file in session.files) == session.total_records
    if scenario == "edge_cases":
        assert 65000 in [event.fields["event_id"] for event in session.analysis_events]


def test_utc_offsets_account_keys_and_original_values_are_preserved(record):
    second = deepcopy(record)
    second.update(timestamp="2026-01-15T12:05:00+03:00", target_user="ALICE",
                  target_domain="lab", hostname="lab-pc01", target_logon_id="0X00001234")
    session = ImportSession()
    imported, = session.import_files([json_file([record, second])])
    assert imported.duplicates == 1
    event, = detection_events(session)
    assert event.timestamp_utc == datetime(2026, 1, 15, 9, 5, tzinfo=timezone.utc)
    assert event.fields["target_user"] == "alice"
    assert event.fields["target_domain"] == "lab"
    assert event.fields["hostname"] == "lab-pc01"
    assert event.fields["target_logon_id"] == "0x1234"
    assert event.fields["subject_logon_id"] is None
    original = event.occurrences[1]
    assert original.original_fields == second
    assert original.original_timestamp == "2026-01-15T12:05:00+03:00"
    assert original.original_offset == "+03:00"


def test_equivalent_ipv6_and_ipv4_mapped_addresses(record):
    variants = [deepcopy(record) for _ in range(4)]
    for row, address in zip(variants, [
        "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1",
        "192.0.2.10", "::ffff:192.0.2.10",
    ]):
        row["source_ip"] = address
    session = ImportSession()
    imported, = session.import_files([json_file(variants)])
    assert imported.accepted == 4
    assert imported.duplicates == 2
    assert {event.fields["source_ip"] for event in session.analysis_events} == {
        "2001:db8::1", "192.0.2.10",
    }


@pytest.mark.parametrize("address", ["not-an-ip", "192.0.2.999", 123, True])
def test_invalid_ip_addresses_are_located_rejections(record, address):
    record["source_ip"] = address
    session = ImportSession()
    imported, = session.import_files([json_file([record])])
    assert (imported.accepted, imported.rejected) == (0, 1)
    assert "source_ip" in session.errors[0].message
    assert session.errors[0].line_start == 1


def test_timezone_must_be_selected_for_naive_time_and_assumption_is_recorded(record):
    record["timestamp"] = "2026-01-15T12:05:00"
    session = ImportSession()
    file = json_file([record])
    rejected, = session.import_files([file])
    assert rejected.rejected == 1
    assert "explicitly select" in session.errors[0].message
    accepted, = session.import_files([file], assumed_timezone="Asia/Amman")
    assert accepted.accepted == 1
    event, = session.analysis_events
    assert event.timestamp_utc.hour == 9
    occurrence, = event.occurrences
    assert occurrence.original_timestamp == record["timestamp"]
    assert occurrence.original_offset is None
    assert occurrence.assumed_timezone == "Asia/Amman"
    assert occurrence.resolved_offset == "+0300"
    assert rejected.sha256 == accepted.sha256


@pytest.mark.parametrize(
    "timestamp,message",
    [
        ("2026-11-01T01:30:00", "ambiguous"),
        ("2026-03-08T02:30:00", "nonexistent"),
    ],
)
def test_daylight_saving_fold_and_gap_require_correction(record, timestamp, message):
    record["timestamp"] = timestamp
    session = ImportSession()
    imported, = session.import_files([json_file([record])], assumed_timezone="America/New_York")
    assert imported.rejected == 1
    assert message in session.errors[0].message
    assert len(session.analysis_events) == 0


def test_explicit_offsets_disambiguate_dst_and_ignore_selected_zone(record):
    first, second = deepcopy(record), deepcopy(record)
    first["timestamp"], second["timestamp"] = "2026-11-01T01:30:00-04:00", "2026-11-01T01:30:00-05:00"
    session = ImportSession()
    imported, = session.import_files(
        [json_file([first, second])], assumed_timezone="Asia/Amman",
    )
    assert (imported.accepted, imported.duplicates) == (2, 0)
    assert [event.timestamp_utc.hour for event in session.analysis_events] == [5, 6]
    assert all(event.occurrences[0].assumed_timezone is None for event in session.analysis_events)


def test_missing_optional_fields_are_null_but_timeline_fields_are_required(record):
    minimal = {name: record[name] for name in (
        "timestamp", "event_id", "hostname", "record_id", "provider", "channel",
    )}
    missing_host = deepcopy(minimal)
    del missing_host["hostname"]
    session = ImportSession()
    imported, = session.import_files([json_file([minimal, missing_host])])
    assert (imported.accepted, imported.rejected) == (1, 1)
    assert session.analysis_events[0].fields["target_user"] is None
    assert session.analysis_events[0].fields["source_ip"] is None
    assert "hostname" in session.errors[0].message
    assert session.errors[0].record_position == 2
    assert session.analysis_events[0].occurrences[0].original_fields == minimal


def test_distinct_records_do_not_merge_on_time_and_event_id(record):
    variants = [deepcopy(record) for _ in range(4)]
    variants[1]["record_id"] += 1
    variants[2]["target_user"] = "bob"
    variants[3]["task_content"] = "different preserved text"
    session = ImportSession()
    imported, = session.import_files([json_file(variants)])
    assert imported.new_events == 4
    assert imported.duplicates == 0


@pytest.mark.parametrize("filename,content", [
    ("empty.csv", b""), ("empty.jsonl", b""), ("whitespace.jsonl", b" \n\r\n"),
    ("header.csv", (",".join(EVENT_FIELDS) + "\n").encode()),
])
def test_empty_and_header_only_files_have_zero_record_denominator(filename, content):
    session = ImportSession()
    imported, = session.import_files([InputFile(filename, content)])
    assert imported.input_records == imported.accepted == imported.rejected == 0
    assert imported.file_error is None
    assert imported.sha256 == sha256(content).hexdigest()


def test_malformed_jsonl_recovers_per_line_and_preserves_physical_positions(record):
    data = b"\n{bad json}\n[]\n" + json_file([record]).content
    session = ImportSession()
    imported, = session.import_files([InputFile("malformed.jsonl", data)])
    assert (imported.input_records, imported.accepted, imported.rejected) == (3, 1, 2)
    assert [error.line_start for error in session.errors] == [2, 3]
    assert [error.record_position for error in session.errors] == [2, 3]
    assert "Malformed JSONL" in session.errors[0].message
    assert session.analysis_events[0].occurrences[0].line_start == 4


def test_csv_multiline_text_and_bad_record_locations(record):
    record["task_content"] = "<Task>\r\nSYNTHETIC marker\r\n</Task>"
    data = csv_file([record]).content
    data += b"too,few,cells\r\n"
    session = ImportSession()
    imported, = session.import_files([InputFile("multi.csv", data)])
    assert (imported.input_records, imported.accepted, imported.rejected) == (2, 1, 1)
    occurrence, = session.analysis_events[0].occurrences
    assert occurrence.line_start == 2 and occurrence.line_end == 4
    assert occurrence.original_fields["task_content"] == record["task_content"]
    assert session.errors[0].line_start == 5
    assert "header defines" in session.errors[0].message


def test_unclosed_csv_quote_rejects_remaining_record_without_hanging(record):
    header = csv_file([]).content
    session = ImportSession()
    imported, = session.import_files([InputFile("bad.csv", header + b'"unclosed\nrest')])
    assert imported.rejected == 1
    assert "Malformed CSV" in session.errors[0].message
    assert session.errors[0].line_start == 2
    assert session.errors[0].line_end == 3


@pytest.mark.parametrize("filename,content,message", [
    ("binary.csv", b"\xff\xfe\x00", "UTF-8"),
    ("binary.jsonl", b"\x00{}", "NUL"),
    ("missing.csv", b"event_id,timestamp\n4624,2026-01-15T00:00:00Z\n", "missing required"),
    ("duplicate.csv", b"timestamp,timestamp\nx,y\n", "unique"),
    ("file.txt", b"{}", "extension"),
])
def test_unreadable_files_fail_without_accepting_records(filename, content, message):
    session = ImportSession()
    imported, = session.import_files([InputFile(filename, content)])
    assert message in imported.file_error
    assert imported.original_bytes == content
    assert imported.input_records == imported.rejected == imported.accepted == 0
    assert not session.analysis_events


def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected():
    session = ImportSession()
    imported, = session.import_files([InputFile(
        "invalid.jsonl", b'{"event_id":4624,"event_id":4625}\n{"event_id":NaN}\n',
    )])
    assert imported.rejected == 2
    assert "duplicate JSON field" in session.errors[0].message
    assert "nonstandard JSON" in session.errors[1].message


def test_unicode_line_separator_in_text_is_not_a_new_record(record):
    record["task_content"] = "preserve\u2028this"
    data = (json.dumps(record, ensure_ascii=False) + "\n").encode()
    session = ImportSession()
    imported, = session.import_files([InputFile("unicode.jsonl", data)])
    assert imported.input_records == imported.accepted == 1
    assert session.analysis_events[0].occurrences[0].source_record.encode() == data


def test_file_and_session_byte_limits_are_exact_and_atomic():
    assert MAX_FILE_BYTES == 10_000_000
    assert MAX_SESSION_BYTES == 20_000_000
    session = ImportSession()
    session.import_files([InputFile("empty.csv", b" " * MAX_FILE_BYTES)])
    with pytest.raises(ImportLimitError, match="per-file"):
        session.import_files([InputFile("large.csv", b" " * (MAX_FILE_BYTES + 1))])
    assert len(session.files) == 1
    session.import_files([InputFile("empty2.csv", b" " * MAX_FILE_BYTES)])
    assert session.total_bytes == MAX_SESSION_BYTES
    with pytest.raises(ImportLimitError, match="session"):
        session.import_files([InputFile("one.csv", b" ")])
    assert len(session.files) == 2


def test_record_limit_counts_rejections_and_rolls_back_entire_batch():
    assert MAX_INPUT_RECORDS == 50_000
    session = ImportSession()
    session.import_files([InputFile("invalid.jsonl", b"{}\n" * 50_000)])
    assert session.total_records == len(session.errors) == 50_000
    before_bytes = session.total_bytes
    with pytest.raises(ImportLimitError, match="50,000"):
        session.import_files([InputFile("extra.jsonl", b"{}\n")])
    assert len(session.files) == 1
    assert session.total_records == 50_000
    assert session.total_bytes == before_bytes


def test_excess_batch_does_not_commit_first_file(record, monkeypatch):
    monkeypatch.setattr("incident_analyzer.ingestion.MAX_INPUT_RECORDS", 1)
    session = ImportSession()
    with pytest.raises(ImportLimitError):
        session.import_files([json_file([record], "first.jsonl"), json_file([record], "second.jsonl")])
    assert session.total_bytes == session.total_records == 0
    assert not session.files and not session.events and not session.errors


def test_sessions_do_not_share_normalized_events_or_provenance(record):
    first, second = ImportSession(), ImportSession()
    first.import_files([json_file([record])])
    assert not second.files and not second.events and not second.errors
