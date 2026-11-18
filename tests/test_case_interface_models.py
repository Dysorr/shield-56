"""Independent display-scope, state isolation/reset, and manifest contracts."""

from datetime import date, timedelta
import json

import pytest

from incident_analyzer.case_state import (
    DISPOSITIONS, ensure_case, reset_case, save_conclusion, save_finding_note, uploader_key,
)
from incident_analyzer.detection import analyze
from incident_analyzer.evidence_manifest import build_manifest, manifest_json
from incident_analyzer.ingestion import ImportSession
from incident_analyzer.models import InputFile
from incident_analyzer.timeline_filters import account_label, filter_timeline, volume_bins
from scripts.generate_synthetic import render_jsonl
from scripts.synthetic_scenarios import build_scenarios


def case_session(name="suspicious_sequence"):
    session = ImportSession()
    session.import_files([InputFile(f"{name}.jsonl", render_jsonl(build_scenarios()[name]))])
    return session


def test_each_filter_and_intersection_preserve_full_case_analysis():
    session = case_session()
    events = session.analysis_events
    before = analyze(session)
    assert len(events) == 19
    matching = filter_timeline(
        events, start_date=date(2026, 1, 15), end_date=date(2026, 1, 15),
        hosts=["lab-pc01"], accounts=["lab\\alice"], event_ids=["4625"],
        source_ips=["192.0.2.10"],
    )
    assert [event.fields["record_id"] for event in matching] == [2101, 2102, 2103, 2104, 2105]
    for kwargs in [
        {"start_date": date(2026, 1, 16)}, {"end_date": date(2026, 1, 14)},
        {"hosts": ["different-host"]}, {"accounts": ["lab\\different"]},
        {"event_ids": ["99999"]}, {"source_ips": ["192.0.2.99"]},
    ]:
        assert filter_timeline(events, **kwargs) == []
    after = analyze(session)
    assert [f.finding_id for f in before.findings] == [f.finding_id for f in after.findings]
    assert len(session.events) == 19


def test_account_filter_respects_task_creator_and_nulls():
    events = case_session().analysis_events
    task = next(event for event in events if event.fields["record_id"] == 2107)
    assert account_label(task) == "lab\\alice"
    assert task in filter_timeline(events, accounts=["lab\\alice"])
    assert task in filter_timeline(events, source_ips=[None])
    assert task not in filter_timeline(events, source_ips=["192.0.2.10"])


def test_utc_dates_are_inclusive_and_invalid_range_is_clear():
    rows = build_scenarios()["suspicious_sequence"][-7:-4]
    rows[0]["timestamp"] = "2026-01-16T02:59:59.999999+03:00"
    rows[1]["timestamp"] = "2026-01-16T03:00:00+03:00"
    rows[2]["timestamp"] = "2026-01-15T00:00:00Z"
    session = ImportSession()
    session.import_files([InputFile("dates.jsonl", render_jsonl(rows))])
    shown = filter_timeline(session.analysis_events, start_date=date(2026, 1, 15), end_date=date(2026, 1, 15))
    assert [event.fields["record_id"] for event in shown] == [2103, 2101]
    with pytest.raises(ValueError, match="start date"):
        filter_timeline(session.analysis_events, start_date=date(2026, 1, 16), end_date=date(2026, 1, 15))


def test_volume_totals_zero_gaps_and_duplicate_distinction():
    session = case_session()
    events = filter_timeline(session.analysis_events, event_ids=["4625"])
    bins, width = volume_bins(events)
    assert width == 60
    assert sum(row["Distinct events"] for row in bins) == len(events)
    assert all(row["UTC bin start"].endswith("+00:00") for row in bins)
    sparse = [events[0], events[-1]]
    bins, _ = volume_bins(sparse)
    assert sum(row["Distinct events"] for row in bins) == 2
    assert any(row["Distinct events"] == 0 for row in bins)
    assert volume_bins([]) == ([], 60)
    one, _ = volume_bins([events[0]])
    assert len(one) == 1 and one[0]["Distinct events"] == 1


def test_volume_bins_are_bounded_across_wide_date_ranges():
    events = list(case_session().analysis_events[:2])
    events[-1].timestamp_utc += timedelta(days=10000)
    bins, _ = volume_bins(events)
    assert len(bins) <= 240
    assert sum(row["Distinct events"] for row in bins) == 2


def test_manifest_is_full_case_and_contains_exact_provenance_and_assumptions():
    session = case_session("edge_cases")
    original = build_scenarios()["edge_cases"]
    session.import_files([InputFile("again.jsonl", render_jsonl(original))], assumed_timezone="Asia/Amman")
    data = build_manifest(session)
    assert "Full case" in data["scope"]
    assert data["counts"]["files"] == 2
    assert data["counts"]["input_records"] == 20
    assert data["counts"]["accepted_occurrences"] == 17
    assert data["counts"]["rejected_records"] == 3
    assert data["counts"]["distinct_events"] == 8
    assert data["files"][1]["assumed_timezone"] == "Asia/Amman"
    assert data["files"][0]["sha256"] == session.files[0].sha256
    assert len(data["events"]) == 8
    assert any(
        source["assumed_timezone"] == "Asia/Amman"
        for event in data["events"] for source in event["sources"]
    )
    assert json.loads(manifest_json(session)) == data
    assert "original_bytes" not in data["files"][0]
    assert len(data["validation_locations"]) == 3


def test_saved_notes_survive_reruns_and_different_sessions_stay_isolated():
    first, second = {}, {}
    ensure_case(first)
    ensure_case(second)
    first["imports"] = case_session()
    finding = analyze(first["imports"]).findings[0]
    save_finding_note(first, finding, "<script>Literal analyst note</script>", DISPOSITIONS[1])
    save_conclusion(first, "Review service credentials", DISPOSITIONS[0])
    ensure_case(first)
    assert first["finding_notes"][finding.finding_id]["note"] == "<script>Literal analyst note</script>"
    assert first["case_conclusion"] == "Review service credentials"
    assert second["finding_notes"] == {}
    assert second["case_conclusion"] == ""
    assert first["imports"] is not second["imports"]
    for state_key in ("finding_notes", "investigation"):
        assert first[state_key] is not second[state_key]


def test_reset_clears_every_case_value_and_rotates_uploader_identity():
    state = {}
    ensure_case(state)
    first_key = uploader_key(state)
    state["imports"] = case_session()
    finding = analyze(state["imports"]).findings[0]
    save_finding_note(state, finding, "old note", DISPOSITIONS[2])
    save_conclusion(state, "old conclusion", DISPOSITIONS[1])
    state.update({
        first_key: [b"uploaded private bytes"],
        "derived_results": analyze(state["imports"]),
        "tl_search": "private query",
        "evidence_focus": finding.supporting_event_keys[0],
        "notes_draft": "private draft",
    })
    reset_case(state)
    assert not state["imports"].files
    assert not state["finding_notes"] and not state["case_conclusion"]
    assert uploader_key(state) != first_key
    assert first_key not in state
    assert "derived_results" not in state
    assert "tl_search" not in state and "evidence_focus" not in state
    assert "notes_draft" not in state
    assert state["case_disposition"] == "needs investigation"
    assert state["case_reset_message"]


@pytest.mark.parametrize("disposition", DISPOSITIONS)
def test_exact_dispositions_supported(disposition):
    state = {}
    save_conclusion(state, "text", disposition)
    assert state["case_disposition"] == disposition


def test_invalid_notes_rejected_without_changing_prior_save():
    state = {}
    save_conclusion(state, "prior", DISPOSITIONS[0])
    with pytest.raises(ValueError):
        save_conclusion(state, "too long" * 5000, DISPOSITIONS[0])
    with pytest.raises(ValueError):
        save_conclusion(state, "new", "confirmed compromise")
    assert state["case_conclusion"] == "prior"
