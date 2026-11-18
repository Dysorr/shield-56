"""Input validation must not silently change evidence or account roles."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from incident_analyzer.schema import (
    EVENT_FIELDS, EventValidationError, SecurityEvent, decode_csv_record,
)
from scripts.synthetic_scenarios import build_scenarios


@pytest.fixture
def valid_record():
    return deepcopy(build_scenarios()["suspicious_sequence"][-2])


def test_roles_and_logon_ids_are_not_interchanged():
    records = build_scenarios()["suspicious_sequence"]
    success, task = map(SecurityEvent.from_mapping, records[-2:])
    assert (success.target_domain, success.target_user) == ("LAB", "alice")
    assert success.subject_user is None
    assert (task.subject_domain, task.subject_user) == ("LAB", "alice")
    assert task.target_user is None
    assert success.target_logon_id == task.subject_logon_id == "0x1234"
    assert success.subject_logon_id is task.target_logon_id is None


def test_preserves_original_offset_and_provides_aware_utc(valid_record):
    valid_record["timestamp"] = "2026-01-15T12:05:00+03:00"
    event = SecurityEvent.from_mapping(valid_record)
    assert event.timestamp == valid_record["timestamp"]
    assert event.timestamp_utc == datetime(2026, 1, 15, 9, 5, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "timestamp",
    ["not-a-timestamp", "2026-01-15T09:05:00", "2026-02-30T09:05:00Z",
     "2026-01-15", "2026-01-15T09:05:00+25:00", "2026-01-15T09:05:00+03:60"],
)
def test_rejects_invalid_or_naive_timestamps(valid_record, timestamp):
    valid_record["timestamp"] = timestamp
    with pytest.raises(EventValidationError, match="timestamp"):
        SecurityEvent.from_mapping(valid_record)


@pytest.mark.parametrize(
    "field,value",
    [("record_id", True), ("event_id", "4624"), ("record_id", 0),
     ("logon_type", 3.0), ("source_ip", "not-an-ip"),
     ("target_logon_id", "1234"), ("hostname", ""),
     ("target_user", None), ("channel", None)],
)
def test_rejects_incorrect_types_and_values(valid_record, field, value):
    valid_record[field] = value
    with pytest.raises(EventValidationError, match=field):
        SecurityEvent.from_mapping(valid_record)


def test_missing_source_ip_is_null_not_a_guessed_address(valid_record):
    valid_record["source_ip"] = None
    assert SecurityEvent.from_mapping(valid_record).source_ip is None


def test_csv_empty_cells_are_null_without_coercing_hex_ids(valid_record):
    row = {field: "" if value is None else str(value)
           for field, value in valid_record.items()}
    assert decode_csv_record(row) == valid_record
    assert SecurityEvent.from_mapping(decode_csv_record(row)).target_logon_id == "0x1234"


def test_missing_and_unknown_columns_are_explicit(valid_record):
    del valid_record["task_content"]
    valid_record["wrong_column"] = "unexpected"
    with pytest.raises(EventValidationError, match="fields"):
        SecurityEvent.from_mapping(valid_record)


def test_unknown_id_and_html_like_text_are_preserved():
    records = build_scenarios()["edge_cases"]
    unknown = SecurityEvent.from_mapping(records[-2])
    html = SecurityEvent.from_mapping(records[-1])
    assert unknown.event_id == 65000
    assert html.task_name == "<script>alert('SYNTHETIC ONLY')</script>"
    assert tuple(records[-1]) == EVENT_FIELDS


def test_record_identity_includes_host_provider_and_channel(valid_record):
    first = SecurityEvent.from_mapping(valid_record)
    valid_record["hostname"] = "OTHER-LAB-PC"
    second = SecurityEvent.from_mapping(valid_record)
    assert first.record_id == second.record_id
    assert first.source_identity != second.source_identity
