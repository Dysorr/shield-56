"""Full-case exports are deterministic, traceable, literal and session-local."""

from datetime import datetime, timezone
from html import unescape
import json
from pathlib import Path
import re

from streamlit.testing.v1 import AppTest

from incident_analyzer.case_state import ensure_case, reset_case, save_conclusion, save_finding_note
from incident_analyzer.detection import analyze
from incident_analyzer.models import InputFile
from incident_analyzer.reporting import TITLE, build_exports

STAMP = datetime(2026, 1, 16, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def state_for(name="suspicious_sequence"):
    state = {}
    ensure_case(state)
    path = ROOT / "data/synthetic/xml" / f"{name}.synthetic.xml"
    state["imports"].import_files([InputFile(path.name, path.read_bytes())])
    return state


def test_xml_reports_capture_expected_full_case_findings_and_every_reference():
    state = state_for()
    result = analyze(state["imports"])
    save_finding_note(state, result.findings[-1], "Verify authorized lab maintenance.", "expected activity")
    save_conclusion(state, "Synthetic exercise; authorization not yet confirmed.", "needs investigation")
    export = build_exports(state, STAMP)
    snapshot = export.snapshot
    assert snapshot["title"] == TITLE
    assert snapshot["summary"]["distinct_events"] == 19
    assert snapshot["summary"]["findings"] == 3
    assert [f["rule_id"] for f in snapshot["findings"]] == ["R1", "R2", "R3"]
    assert snapshot["findings"][-1]["analyst_note"]["disposition"] == "expected activity"
    assert snapshot["case_conclusion"]["text"] == state["case_conclusion"]
    assert snapshot["configuration"]["success_window_minutes"] == 10
    assert snapshot["rule_versions"] == {"R1": "1.0.0", "R2": "1.0.0", "R3": "1.0.0"}
    keys = {e["event_key"] for e in snapshot["evidence"]}
    references = {o["source_ref"] for e in snapshot["evidence"] for o in e["occurrences"]}
    for finding in snapshot["findings"]:
        assert set(finding["supporting_event_keys"]) <= keys
        assert set(finding["supporting_event_references"]) <= references
    assert "<Event xmlns=" in snapshot["evidence"][-1]["occurrences"][0]["source_record"]
    assert json.loads(export.manifest_json) == snapshot["manifest"]
    assert state["imports"].files[0].sha256 in export.markdown
    assert state["imports"].files[0].sha256 in export.html


def test_display_filters_and_drafts_cannot_change_exported_content():
    state = state_for()
    before = build_exports(state, STAMP)
    state.update(tl_search="nothing matches", tl_ids=["99999"], fd_rule="R1",
                 note_drafts={"conclusion:text": "UNSAVED DRAFT"})
    after = build_exports(state, STAMP)
    assert before == after
    assert "UNSAVED DRAFT" not in after.markdown
    assert after.snapshot["case_conclusion"]["status"] == "not saved"


def test_originals_notes_and_markup_are_literal_in_both_formats():
    state = state_for()
    payload = '</pre><script>alert("synthetic")</script>\\n```\\n# Forged conclusion\\n[click](javascript:alert(1))'
    finding = analyze(state["imports"]).findings[0]
    save_finding_note(state, finding, payload, "suspicious activity")
    save_conclusion(state, payload, "needs investigation")
    state["imports"].files[0].filename = payload
    export = build_exports(state, STAMP)
    assert "<script>" not in export.html
    assert "&lt;script&gt;" in export.html
    assert "default-src 'none'" in export.html
    # All potentially unsafe text is inside literal fenced blocks, not active Markdown.
    assert "\n````json\n" in export.markdown
    assert "\n# Forged conclusion\n" not in export.markdown
    contents = re.findall(r"<pre>(.*?)</pre>", export.html, flags=re.S)
    decoded = [json.loads(unescape(block)) for block in contents]
    assert any(isinstance(block, dict) and block.get("text") == payload for block in decoded)


def test_repeated_imports_preserve_occurrences_and_stable_findings():
    state = state_for()
    first = build_exports(state, STAMP)
    imported = state["imports"].files[0]
    state["imports"].import_files([InputFile(imported.filename, imported.original_bytes)])
    second = build_exports(state, STAMP)
    assert second.snapshot["summary"]["distinct_events"] == 19
    assert second.snapshot["summary"]["source_occurrences"] == 38
    assert second.snapshot["manifest"]["counts"]["duplicate_occurrences"] == 19
    assert [f["finding_id"] for f in first.snapshot["findings"]] == [
        f["finding_id"] for f in second.snapshot["findings"]]
    assert all(len(event["occurrences"]) == 2 for event in second.snapshot["evidence"])


def test_snapshot_is_independent_of_subsequent_edits_and_reset():
    state = state_for()
    save_conclusion(state, "Before", "needs investigation")
    original = build_exports(state, STAMP)
    save_conclusion(state, "After", "expected activity")
    assert original.snapshot["case_conclusion"]["text"] == "Before"
    reset_case(state)
    assert build_exports(state, STAMP).snapshot["summary"]["distinct_events"] == 0
    assert len(original.snapshot["evidence"]) == 19


def test_previous_notes_remain_separate_from_current_findings():
    state = state_for("normal_activity")
    state["finding_notes"]["old-id"] = {"note": "Old evidence", "disposition": "needs investigation"}
    export = build_exports(state, STAMP)
    assert export.snapshot["findings"] == []
    assert "does not mean the environment is safe" in export.snapshot["summary"]["interpretation"]
    assert export.snapshot["previous_finding_notes"]["old-id"]["note"] == "Old evidence"


def test_rejected_xml_file_is_reported_without_false_accepted_evidence():
    state = {}
    ensure_case(state)
    state["imports"].import_files([InputFile("bad.xml", b"<Events><Event></Events>")])
    report = build_exports(state, STAMP).snapshot
    assert report["summary"]["distinct_events"] == 0
    assert report["manifest"]["files"][0]["file_error"].startswith("Malformed XML")
    assert report["manifest"]["counts"]["files"] == 1


def test_reports_ui_has_scoped_downloads_and_refreshes_after_reset():
    page = AppTest.from_string("""
import streamlit as st
from incident_analyzer.reports_ui import reports_page
from incident_analyzer.case_ui import render_case_reset
render_case_reset(st)
reports_page(st)
""")
    for key, value in state_for().items():
        page.session_state[key] = value
    page.run(timeout=30)
    assert not page.exception
    assert len(page.get("download_button")) == 0
    page.button(key="prepare_exports_button").click().run(timeout=30)
    assert not page.exception
    assert len(page.get("download_button")) == 8
    page.checkbox(key="reset_confirm_0").check().run()
    page.button(key="reset_button").click().run(timeout=30)
    assert not page.exception
    assert len(page.get("download_button")) == 0
    assert page.info
