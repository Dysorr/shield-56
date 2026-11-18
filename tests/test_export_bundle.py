"""Independently specified export counts, safety, traceability and original-file opt-in."""
import csv
from copy import deepcopy
from datetime import date, datetime, timezone
from hashlib import sha256
import io
import json
from zipfile import ZipFile

import pytest
from streamlit.testing.v1 import AppTest

from incident_analyzer.case_state import ensure_case
from incident_analyzer.export_bundle import (
    FULL_CSV, FILTERED_CSV, FINDINGS_JSON, NOTES_JSON, MANIFEST_JSON,
    REPORT_MD, REPORT_HTML, current_export_signature, csv_safe, prepare_exports, record_download,
)
from incident_analyzer.models import InputFile
from incident_analyzer.report_context import default_judgments, save_judgments
from scripts.generate_synthetic import render_jsonl
from scripts.synthetic_scenarios import build_scenarios

STAMP = datetime(2026, 1, 16, tzinfo=timezone.utc)


def case(name="suspicious_sequence", filename="sample.jsonl"):
    state = {}
    ensure_case(state)
    state["imports"].import_files([InputFile(filename, render_jsonl(build_scenarios()[name]))])
    return state


def csv_rows(data):
    return list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))


def test_default_zip_contains_exactly_safe_derived_files_and_counts():
    state = case(filename="../../malicious.jsonl")
    state["timeline_display_filters"] = {"event_ids": ["4625"], "start_date": date(2026, 1, 15)}
    bundle = prepare_exports(state, generated_at=STAMP)
    with ZipFile(io.BytesIO(bundle.zip_bytes)) as archive:
        assert set(archive.namelist()) == {
            FULL_CSV, FILTERED_CSV, FINDINGS_JSON, NOTES_JSON, MANIFEST_JSON, REPORT_MD, REPORT_HTML,
        }
        assert all(archive.read(name) == data for name, data in bundle.files.items())
        assert all("/" not in name and ".." not in name for name in archive.namelist())
    assert len(csv_rows(bundle.files[FULL_CSV])) == 19
    filtered = csv_rows(bundle.files[FILTERED_CSV])
    assert len(filtered) == 5
    assert [row["record_id"] for row in filtered] == ["2101", "2102", "2103", "2104", "2105"]
    findings = json.loads(bundle.files[FINDINGS_JSON])
    assert len(findings["findings"]) == 3
    assert findings["scope"] == "FULL CASE"
    manifest = json.loads(bundle.files[MANIFEST_JSON])
    assert manifest["timeline_exports"]["filtered"]["count"] == 5
    assert manifest["timeline_exports"]["filtered"]["filters"]["start_date"] == "2026-01-15"
    assert manifest["original_evidence_in_zip"] == []
    assert bundle.snapshot["summary"]["distinct_events"] == 19
    assert len(state["export_history"]) == 1


def test_opt_in_includes_exact_original_bytes_under_generated_safe_names():
    state = case(filename="../../outside.jsonl")
    original = state["imports"].files[0]
    state["imports"].import_files([InputFile("../../outside.jsonl", original.original_bytes)])
    bundle = prepare_exports(state, include_originals=True, generated_at=STAMP)
    manifest = json.loads(bundle.files[MANIFEST_JSON])
    with ZipFile(io.BytesIO(bundle.zip_bytes)) as archive:
        originals = manifest["original_evidence_in_zip"]
        assert len(originals) == 2
        for index, item in enumerate(originals, 1):
            assert item["archive_path"] == f"original_evidence/input_{index:05d}.jsonl"
            assert archive.read(item["archive_path"]) == original.original_bytes
            assert sha256(archive.read(item["archive_path"])).hexdigest() == item["sha256"]
        assert len(archive.namelist()) == 9
    assert len(csv_rows(bundle.files[FULL_CSV])) == 19  # Not 38 duplicate occurrences.


@pytest.mark.parametrize("text", ["=SUM(1,2)", "+cmd", "-1", "@SUM(A1)", "  =cmd", "\tformula", "\rvalue", "\nvalue"])
def test_csv_formula_prefixes_are_escaped(text):
    assert csv_safe(text) == "'" + text


def test_csv_escaping_preserves_canonical_data_and_handles_quotes_newlines():
    state = {}
    ensure_case(state)
    row = build_scenarios()["suspicious_sequence"][-1]
    row["task_name"] = '=HYPERLINK("https://example.invalid","x")\nextra,comma'
    row["task_content"] = "literal, quoted \"text\"\nnext line"
    state["imports"].import_files([InputFile("safe.jsonl", render_jsonl([row]))])
    bundle = prepare_exports(state, generated_at=STAMP)
    csv_row = csv_rows(bundle.files[FULL_CSV])[0]
    assert csv_row["task_name"] == "'" + row["task_name"]
    assert csv_row["task_content"] == row["task_content"]
    assert csv_row["source_ip"] == ""
    assert bundle.snapshot["evidence"][0]["normalized_fields"]["task_name"] == row["task_name"]


def test_empty_filter_exports_header_only_and_full_case_findings_unchanged():
    state = case()
    state["timeline_display_filters"] = {"hosts": ["absent-host"]}
    bundle = prepare_exports(state, generated_at=STAMP)
    assert csv_rows(bundle.files[FILTERED_CSV]) == []
    assert len(csv_rows(bundle.files[FULL_CSV])) == 19
    assert len(json.loads(bundle.files[FINDINGS_JSON])["findings"]) == 3


def test_report_has_required_sections_factual_counts_versions_warnings_and_references():
    state = case("edge_cases")
    state["imports"].import_files([InputFile("broken.xml", b"<Events><Event></Events>")])
    judgments = default_judgments()
    judgments.update(case_title="Training case", observations="Review clock differences",
                     hypotheses="Credential retry", alternative_explanations="Stale service secret")
    save_judgments(state, judgments)
    bundle = prepare_exports(state, generated_at=STAMP)
    report = bundle.files[REPORT_MD].decode()
    for phrase in ("Executive summary", "Training case", "application_version", "SYNTHETIC",
                   "Input = accepted + rejected", "Parser warnings", "Relevant UTC timeline",
                   "hypotheses", "Recommended containment and recovery", "proposed",
                   "Evidence that would help resolve uncertainty", "Evidence-handling record",
                   "from the time of hashing", "Malformed XML"):
        assert phrase in report
    assert bundle.snapshot["manifest"]["counts"]["input_records"] == 10
    assert bundle.snapshot["manifest"]["counts"]["rejected_records"] == 2
    assert bundle.snapshot["manifest"]["files"][1]["file_error"]
    note_export = json.loads(bundle.files[NOTES_JSON])
    assert note_export["judgments"]["hypotheses"] == "Credential retry"
    manifest = json.loads(bundle.files[MANIFEST_JSON])
    assert [operation["operation"] for operation in manifest["evidence_handling"]] == ["import", "import", "export_prepared"]


def test_finding_references_resolve_in_manifest_and_report():
    bundle = prepare_exports(case(), generated_at=STAMP)
    manifest = json.loads(bundle.files[MANIFEST_JSON])
    refs = {source["source_ref"] for event in manifest["events"] for source in event["sources"]}
    for finding in json.loads(bundle.files[FINDINGS_JSON])["findings"]:
        assert set(finding["supporting_event_references"]) <= refs
        assert all(reference in bundle.files[REPORT_MD].decode() for reference in finding["supporting_event_references"])
    snapshot = deepcopy(bundle.snapshot)
    identity = snapshot.pop("report_id")
    assert identity == sha256(json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2, default=str).encode()).hexdigest()


def test_performed_requires_record_and_no_automatic_execution_claim():
    state = case()
    values = default_judgments()
    values["actions"][0]["status"] = "performed"
    with pytest.raises(ValueError, match="who performed"):
        save_judgments(state, values)
    assert "report_judgments" not in state
    values["actions"][0]["performed_record"] = "Analyst recorded approval and lab isolation at 12:00Z, ticket ABC."
    save_judgments(state, values)
    bundle = prepare_exports(state, generated_at=STAMP)
    actions = bundle.snapshot["analyst_judgments"]["actions"]
    assert actions[0]["status"] == "performed" and actions[0]["performed_at_utc"]
    assert actions[1]["status"] == "proposed" and actions[1]["performed_at_utc"] is None
    assert "not independent verification" in bundle.files[REPORT_MD].decode()


def test_prepared_and_download_handling_truthfully_distinguished():
    state = case()
    first = prepare_exports(state, generated_at=STAMP)
    signature = first.signature
    record_download(state, first, FULL_CSV)
    assert current_export_signature(state) == signature
    entry = state["export_history"][-1]
    assert entry["operation"] == "download_requested"
    assert entry["sha256"] == sha256(first.files[FULL_CSV]).hexdigest()
    assert "download_requested" not in first.files[MANIFEST_JSON].decode()
    second = prepare_exports(state, generated_at=STAMP)
    assert "download_requested" in second.files[MANIFEST_JSON].decode()
    state["timeline_display_filters"] = {"query": "alice"}
    assert current_export_signature(state) != signature


def test_ui_prepare_opt_in_and_saved_judgment_invalidates_bundle():
    page = AppTest.from_string("""
import streamlit as st
from incident_analyzer.reports_ui import reports_page
reports_page(st)
""")
    for key, value in case().items():
        page.session_state[key] = value
    page.run(timeout=30)
    assert not page.exception
    assert not page.checkbox(key="include_original_evidence_0").value
    page.button(key="prepare_exports_button").click().run(timeout=30)
    assert not page.exception and len(page.get("download_button")) == 8
    page.checkbox(key="include_original_evidence_0").check().run()
    assert not page.exception and not page.get("download_button")
    page.button(key="prepare_exports_button").click().run(timeout=30)
    assert page.session_state["prepared_exports"].include_originals
    title = next(widget for widget in page.text_input if widget.label == "Case title")
    title.input("Edited case")
    next(button for button in page.button if button.label == "Save analyst judgments").click().run()
    assert not page.exception
    assert page.session_state["report_judgments"]["case_title"] == "Edited case"
    assert not page.get("download_button")
