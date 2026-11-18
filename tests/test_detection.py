"""Independent expectations for rule semantics, boundaries, identity and provenance."""

from collections import Counter
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random

import pytest

from incident_analyzer.detection import analyze
from incident_analyzer.ingestion import ImportSession
from incident_analyzer.models import InputFile
from incident_analyzer.rule_config import DEFAULT_CONFIG, RuleConfig
from scripts.generate_synthetic import render_csv, render_jsonl
from scripts.synthetic_scenarios import build_scenarios

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 1, 15, 9, tzinfo=timezone.utc)


def iso(delta):
    return (BASE + delta).isoformat().replace("+00:00", "Z")


def sequence():
    return deepcopy(build_scenarios()["suspicious_sequence"][-7:])


def session_for(records):
    session = ImportSession()
    session.import_files([InputFile("test.jsonl", render_jsonl(records))])
    return session


def ids(result):
    return [finding.rule_id for finding in result.findings]


def finding(result, rule):
    return next(item for item in result.findings if item.rule_id == rule)


def test_prescribed_sequence_exact_independent_findings_and_support():
    result = analyze(session_for(sequence()))
    assert ids(result) == ["R1", "R2", "R3"]
    assert [[event.record_id for event in f.supporting_events] for f in result.findings] == [
        [2101, 2102, 2103, 2104, 2105],
        [2101, 2102, 2103, 2104, 2105, 2106],
        [2101, 2102, 2103, 2104, 2105, 2106, 2107],
    ]
    assert [f.last_utc for f in result.findings] == [
        BASE + timedelta(minutes=4), BASE + timedelta(minutes=5), BASE + timedelta(minutes=8),
    ]
    for f in result.findings:
        assert f.first_utc == BASE
        assert f.rule_version == "1.0.0"
        assert f.hostname == "lab-pc01"
        assert f.account == "lab\\alice"
        assert f.source_ip == "192.0.2.10"
        assert f.finding_id.startswith(f.rule_id + "-")
        assert f.rule_name and f.explanation and f.severity_rationale
        assert f.benign_explanations and f.analyst_checks
        assert f.severity in ("Medium", "High")
    assert result.configuration == {
        "failure_threshold": 5, "failure_window_minutes": 5,
        "success_window_minutes": 10, "task_window_minutes": 15,
    }
    assert result.rule_versions == {"R1": "1.0.0", "R2": "1.0.0", "R3": "1.0.0"}


@pytest.mark.parametrize("extension,renderer", [("csv", render_csv), ("jsonl", render_jsonl)])
@pytest.mark.parametrize("name,expected", [
    ("normal_activity", []), ("suspicious_sequence", ["R1", "R2", "R3"]), ("edge_cases", []),
])
def test_scenarios_against_independent_expectations_and_separate_key(name, expected, extension, renderer):
    session = ImportSession()
    session.import_files([InputFile(f"sample.{extension}", renderer(build_scenarios()[name]))])
    result = analyze(session)
    assert ids(result) == expected
    # Only evaluation/tests consult the manually specified answer key.
    key = json.loads((ROOT / "evaluation/scenario_answer_key.json").read_text(encoding="utf-8"))
    assert [
        {"rule_id": f.rule_id, "supporting_record_ids": [e.record_id for e in f.supporting_events]}
        for f in result.findings
    ] == key["scenarios"][name]["expected_findings"]


def test_four_distinct_failures_remain_below_threshold_despite_duplicates():
    records = sequence()
    records.pop(4)
    session = session_for(records * 4)
    assert not analyze(session).findings
    session.import_files([InputFile("again.jsonl", render_jsonl(records))])
    assert not analyze(session).findings


@pytest.mark.parametrize("last_microseconds,expected", [
    (299_999_999, ["R1"]), (300_000_000, ["R1"]), (300_000_001, []),
])
def test_r1_inclusive_five_minute_boundary(last_microseconds, expected):
    records = sequence()[:5]
    records[-1]["timestamp"] = iso(timedelta(microseconds=last_microseconds))
    assert ids(analyze(session_for(records))) == expected


@pytest.mark.parametrize("after_final_microseconds,expected", [
    (0, False), (1, True), (599_999_999, True), (600_000_000, True), (600_000_001, False),
])
def test_r2_strict_start_inclusive_ten_minute_end(after_final_microseconds, expected):
    records = sequence()[:6]
    records[-1]["timestamp"] = iso(timedelta(minutes=4, microseconds=after_final_microseconds))
    assert ("R2" in ids(analyze(session_for(records)))) is expected


@pytest.mark.parametrize("after_success_microseconds,expected", [
    (0, False), (1, True), (899_999_999, True), (900_000_000, True), (900_000_001, False),
])
def test_r3_strict_start_inclusive_fifteen_minute_end(after_success_microseconds, expected):
    records = sequence()
    records[-1]["timestamp"] = iso(timedelta(minutes=5, microseconds=after_success_microseconds))
    assert ("R3" in ids(analyze(session_for(records)))) is expected


@pytest.mark.parametrize("field,value", [
    ("hostname", "OTHER-PC"), ("target_user", "bob"), ("target_domain", "OTHER"),
    ("source_ip", "192.0.2.99"), ("target_domain", None), ("target_user", None),
    ("source_ip", None), ("hostname", None),
])
def test_r1_different_or_missing_group_fields_do_not_pool_failures(field, value):
    records = sequence()
    records[0][field] = value
    assert not analyze(session_for(records)).findings


def test_r1_does_not_group_by_logon_type_but_r2_uses_final_type():
    records = sequence()
    records[0]["logon_type"] = 2
    assert ids(analyze(session_for(records))) == ["R1", "R2", "R3"]
    records[4]["logon_type"] = 2
    assert ids(analyze(session_for(records))) == ["R1"]
    records[4]["logon_type"] = None
    assert ids(analyze(session_for(records))) == ["R1"]


@pytest.mark.parametrize("field,value", [
    ("hostname", "OTHER-PC"), ("target_user", "bob"), ("target_domain", "OTHER"),
    ("source_ip", "192.0.2.99"), ("logon_type", 2), ("logon_type", None),
    ("target_user", None), ("target_domain", None), ("source_ip", None),
])
def test_r2_requires_matching_context_and_explicit_compatible_type(field, value):
    records = sequence()
    records[5][field] = value
    assert ids(analyze(session_for(records))) == ["R1"]


@pytest.mark.parametrize("field,value", [
    ("hostname", "OTHER-PC"), ("subject_user", "bob"), ("subject_domain", "OTHER"),
    ("subject_logon_id", "0x9999"), ("subject_logon_id", None),
    ("subject_logon_id", "0x0"), ("subject_domain", None), ("subject_user", None),
])
def test_r3_requires_subject_context_and_nonzero_session(field, value):
    records = sequence()
    records[6][field] = value
    assert ids(analyze(session_for(records))) == ["R1", "R2"]


@pytest.mark.parametrize("value", [None, "0x0"])
def test_missing_or_zero_success_session_prevents_r3_but_not_r2(value):
    records = sequence()
    records[5]["target_logon_id"] = value
    assert ids(analyze(session_for(records))) == ["R1", "R2"]


def test_normalized_hex_and_case_variants_correlate_without_changing_originals():
    records = sequence()
    records[5].update(target_logon_id="0X00001234", target_user="ALICE", target_domain="lab")
    records[6].update(subject_logon_id="0x0001234", subject_user="Alice", hostname="lab-pc01")
    session = session_for(records)
    assert ids(analyze(session)) == ["R1", "R2", "R3"]
    assert next(e for e in session.events.values() if e.fields["event_id"] == 4624).occurrences[0].original_fields["target_logon_id"] == "0X00001234"


def test_task_ip_is_not_invented_or_required_and_ip_context_is_authentication():
    records = sequence()
    records[6]["source_ip"] = "192.0.2.88"
    result = analyze(session_for(records))
    assert finding(result, "R3").source_ip == "192.0.2.10"
    assert "belongs to authentication" in finding(result, "R3").explanation


def test_account_roles_are_not_interchanged_with_other_present_account_fields():
    records = sequence()
    for event in records[:6]:
        event.update(subject_user="unrelated-service", subject_domain="OTHER")
    records[-1].update(target_user="unrelated-target", target_domain="OTHER")
    assert ids(analyze(session_for(records))) == ["R1", "R2", "R3"]


def test_tied_final_failures_with_different_types_do_not_guess_r2_compatibility():
    records = sequence()
    tied = dict(records[4], record_id=6200, logon_type=2)
    assert ids(analyze(session_for([*records, tied]))) == ["R1"]


def test_overlapping_windows_form_one_episode_with_every_supporting_failure():
    template = sequence()[0]
    records = [
        dict(template, timestamp=iso(timedelta(minutes=i)), record_id=4000 + i)
        for i in range(13)
    ]
    result = analyze(session_for(records))
    assert ids(result) == ["R1"]
    assert len(result.findings[0].supporting_events) == 13
    assert result.findings[0].last_utc - result.findings[0].first_utc == timedelta(minutes=12)


def test_success_during_extended_episode_is_not_after_final_failure():
    records = [
        dict(sequence()[0], timestamp=iso(timedelta(minutes=i)), record_id=4000 + i)
        for i in range(10)
    ] + [dict(sequence()[5], timestamp=iso(timedelta(minutes=8, seconds=30)))]
    assert ids(analyze(session_for(records))) == ["R1"]


def test_multiple_successes_select_earliest_and_do_not_emit_duplicate_r2():
    records = sequence()
    later = dict(records[5], timestamp=iso(timedelta(minutes=6)), record_id=4200,
                 target_logon_id="0x5678")
    result = analyze(session_for([later, *records]))
    assert ids(result) == ["R1", "R2", "R3"]
    assert finding(result, "R2").supporting_events[-1].record_id == 2106


def test_success_assigns_to_nearest_eligible_episode_only():
    template = sequence()[0]
    records = [
        dict(template, timestamp=iso(timedelta(minutes=minute)), record_id=5000 + index)
        for index, minute in enumerate([0, 1, 2, 3, 4, 7, 8, 9, 10, 11])
    ]
    records.append(dict(sequence()[5], timestamp=iso(timedelta(minutes=12))))
    result = analyze(session_for(records))
    assert Counter(ids(result)) == {"R1": 2, "R2": 1}
    assert [event.record_id for event in finding(result, "R2").supporting_events] == [
        5005, 5006, 5007, 5008, 5009, 2106,
    ]


@pytest.mark.parametrize("same_account", [False, True])
def test_intervening_host_session_id_reuse_blocks_old_r3_link(same_account):
    records = sequence()
    later = dict(records[5], timestamp=iso(timedelta(minutes=7)), record_id=6000,
                 target_user="alice" if same_account else "bob")
    assert ids(analyze(session_for([*records, later]))) == ["R1", "R2"]


def test_other_host_session_reuse_does_not_block_r3():
    records = sequence()
    other = dict(records[5], timestamp=iso(timedelta(minutes=7)), record_id=6000, hostname="OTHER-PC")
    assert ids(analyze(session_for([*records, other]))) == ["R1", "R2", "R3"]


def test_tied_latest_logons_are_ambiguous_for_r3():
    records = sequence()
    tied = dict(records[5], record_id=6000)
    assert ids(analyze(session_for([*records, tied]))) == ["R1", "R2"]


def test_one_r3_per_success_retains_every_distinct_task_not_duplicate_occurrences():
    records = sequence()
    task = dict(records[-1], timestamp=iso(timedelta(minutes=9)), record_id=6001)
    result = analyze(session_for([*records, task, task]))
    assert Counter(ids(result)) == {"R1": 1, "R2": 1, "R3": 1}
    r3 = finding(result, "R3")
    assert [event.record_id for event in r3.supporting_events][-2:] == [2107, 6001]
    assert len(r3.source_occurrences) == 9  # Seven source rows, new task, repeated task.


def test_out_of_order_and_duplicate_imports_keep_stable_ids_with_every_reference():
    records = sequence()
    session = session_for(records)
    first = analyze(session)
    shuffled = deepcopy(records)
    random.Random(910).shuffle(shuffled)
    reordered = analyze(session_for(shuffled))
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in reordered.findings]
    session.import_files([InputFile("same.csv", render_csv(records))])
    repeated = analyze(session)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in repeated.findings]
    assert [len(f.source_occurrences) for f in repeated.findings] == [10, 12, 14]
    assert [len(f.supporting_event_references) for f in repeated.findings] == [10, 12, 14]
    session.import_files([InputFile("again.jsonl", render_jsonl(records))])
    again = analyze(session)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in again.findings]
    assert [len(f.source_occurrences) for f in again.findings] == [15, 18, 21]
    assert len(finding(again, "R3").supporting_event_references) == 14
    for event in finding(again, "R3").supporting_events:
        assert len(event.source_occurrences) == 3
        assert len(event.source_references) == 2
        assert all(occ.original_fields["record_id"] in (str(event.record_id), event.record_id)
                   for occ in event.source_occurrences)


def test_configuration_is_recorded_and_changes_ids_and_behavior():
    session = session_for(sequence())
    baseline = analyze(session)
    assert baseline.configuration == asdict(DEFAULT_CONFIG)
    custom = RuleConfig(failure_threshold=6)
    assert analyze(session, custom).findings == ()
    altered = analyze(session, RuleConfig(success_window_minutes=11))
    assert ids(altered) == ["R1", "R2", "R3"]
    assert [f.finding_id for f in baseline.findings] != [f.finding_id for f in altered.findings]
    assert altered.configuration["success_window_minutes"] == 11


@pytest.mark.parametrize("kwargs", [
    {"failure_threshold": 1}, {"failure_threshold": True},
    {"success_window_minutes": 0}, {"task_window_minutes": 1.5},
])
def test_invalid_configuration_fails_explicitly(kwargs):
    with pytest.raises(ValueError):
        RuleConfig(**kwargs)


def test_empty_analysis_records_configuration_without_claiming_safety():
    result = analyze(ImportSession())
    assert not result.findings
    assert result.distinct_events == result.source_occurrences == 0
    assert result.configuration["success_window_minutes"] == 10
