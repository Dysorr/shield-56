"""Normal Streamlit widget interactions: filters, source selection, notes and full reset."""

import json
from datetime import date

from streamlit.testing.v1 import AppTest

from incident_analyzer.case_state import ensure_case, uploader_key
from incident_analyzer.detection import analyze
from incident_analyzer.ingestion import ImportSession
from incident_analyzer.models import InputFile
from incident_analyzer.timeline_ui import chart_spec
from scripts.generate_synthetic import render_jsonl
from scripts.synthetic_scenarios import build_scenarios

HARNESS = """
import streamlit as st
from incident_analyzer.case_state import ensure_case
from incident_analyzer.case_ui import render_case_notice, render_case_reset
from incident_analyzer.ingestion_ui import import_page
from incident_analyzer.timeline_ui import timeline_page
from incident_analyzer.findings_ui import findings_page
from incident_analyzer.evidence_ui import evidence_page
from incident_analyzer.notes_ui import notes_page
from incident_analyzer.reports_ui import reports_page
ensure_case(st.session_state)
render_case_reset(st)
render_case_notice(st)
views = {"Import": import_page, "Timeline": timeline_page, "Findings": findings_page,
         "Evidence": evidence_page, "Analyst notes": notes_page, "Reports": reports_page}
view = st.selectbox("Test view", list(views), key="test_view")
views[view](st)
"""


def page_for(view="Import", dataset=None):
    page = AppTest.from_string(HARNESS)
    if dataset:
        session = ImportSession()
        session.import_files([InputFile("sample.jsonl", render_jsonl(build_scenarios()[dataset]))])
        page.session_state["imports"] = session
    page.session_state["test_view"] = view
    return page.run(timeout=30)


def switch(page, view):
    page.selectbox(key="test_view").select(view).run(timeout=30)
    assert not page.exception


def selected_box(page, key):
    return next(item for item in page.selectbox if item.key.startswith(key + "__"))


def test_import_filter_inspect_notes_and_reset_normal_widgets():
    page = page_for()
    page.selectbox(key="synthetic_dataset").select("suspicious_sequence")
    page.button(key="import_synthetic").click().run()
    assert not page.exception
    assert len(page.session_state["imports"].events) == 19
    assert len(page.get("download_button")) == 1
    switch(page, "Timeline")
    page.multiselect(key="tl_hosts").select("lab-pc01")
    page.multiselect(key="tl_accounts").select("lab\\alice")
    page.multiselect(key="tl_ids").select("4625")
    page.multiselect(key="tl_ips").select("192.0.2.10")
    page.date_input(key="tl_start").set_value(date(2026, 1, 15))
    page.date_input(key="tl_end").set_value(date(2026, 1, 15)).run()
    assert not page.exception
    assert [item.value for item in page.metric] == ["19", "5"]
    table = next(item.value for item in page.dataframe if "Timestamp (UTC)" in item.value.columns)
    assert list(table["record_id"]) == [2101, 2102, 2103, 2104, 2105]
    assert table["Timestamp (UTC)"].is_monotonic_increasing
    switch(page, "Findings")
    assert [item.value for item in page.metric] == ["19", "19", "3"]
    page.selectbox(key="fd_rule").select("R3").run()
    selected = page.session_state["selected_finding_id"]
    switch(page, "Analyst notes")
    assert selected_box(page, "notes_finding").value == selected
    page.text_area(key=f"note_text_0_{selected}").input("Validate authorized administrator change.")
    page.selectbox(key=f"note_disp_0_{selected}").select("expected activity")
    page.button(key=f"note_save_0_{selected}").click().run()
    page.text_area(key="conclusion_text_0").input("Lab exercise; confirm owner authorization.")
    page.selectbox(key="conclusion_disp_0").select("needs investigation")
    page.button(key="conclusion_save_0").click().run()
    assert not page.exception
    switch(page, "Evidence")
    switch(page, "Analyst notes")
    assert page.text_area(key=f"note_text_0_{selected}").value == "Validate authorized administrator change."
    assert page.text_area(key="conclusion_text_0").value == "Lab exercise; confirm owner authorization."
    assert not page.checkbox(key="reset_confirm_0").value
    assert page.button(key="reset_button").disabled
    page.checkbox(key="reset_confirm_0").check().run()
    page.button(key="reset_button").click().run()
    assert not page.exception
    assert not page.session_state["imports"].files
    assert page.session_state["finding_notes"] == {}
    assert page.session_state["case_conclusion"] == ""
    assert page.session_state["case_generation"] == 1
    assert page.file_uploader[0].key == "uploads_1"
    assert not page.file_uploader[0].value
    assert page.button(key="import_uploads").disabled
    assert not page.checkbox(key="reset_confirm_1").value
    assert page.button(key="reset_button").disabled


def test_empty_views_and_conclusion_without_findings():
    page = page_for()
    for view in ("Timeline", "Evidence", "Findings", "Analyst notes"):
        switch(page, view)
        assert page.info
    page.text_area(key="conclusion_text_0").input("Awaiting evidence")
    page.button(key="conclusion_save_0").click().run()
    assert page.session_state["case_conclusion"] == "Awaiting evidence"
    assert not page.exception


def test_evidence_selection_not_locked_by_navigation_focus_and_text_is_literal():
    page = page_for("Evidence", "edge_cases")
    events = list(page.session_state["imports"].analysis_events)
    html = next(event for event in events if event.fields["record_id"] == 3009)
    other = next(event for event in events if event.fields["record_id"] == 3008)
    page.session_state["evidence_focus"] = html.event_key
    page.run()
    assert selected_box(page, "ev_event").value == html.event_key
    assert any("<script>" in item.value for item in page.code)
    assert not any("<script>" in item.value for item in page.markdown)
    assert any("File SHA-256:" in item.value for item in page.text)
    selected_box(page, "ev_event").select(other.event_key).run()
    assert not page.exception
    assert selected_box(page, "ev_event").value == other.event_key
    page.text_input(key="ev_find").input("no-such-event").run()
    assert any("No events match" in item.value for item in page.info)


def test_timeline_invalid_dates_zero_results_and_clear_filters():
    page = page_for("Timeline", "suspicious_sequence")
    page.date_input(key="tl_start").set_value(date(2026, 1, 16))
    page.date_input(key="tl_end").set_value(date(2026, 1, 15)).run()
    assert "start date" in page.error[0].value
    page.button(key="tl_clear").click().run()
    assert not page.exception
    assert page.date_input(key="tl_start").value is None
    assert [item.value for item in page.metric] == ["19", "19"]
    page.text_input(key="tl_search").input("nonexistent-value").run()
    assert [item.value for item in page.metric] == ["19", "0"]
    assert any("No events match" in item.value for item in page.info)
    switch(page, "Findings")
    assert page.metric[2].value == "3"


def test_notes_are_independent_per_finding_literal_and_retained_when_ids_change():
    page = page_for("Analyst notes", "suspicious_sequence")
    result = analyze(page.session_state["imports"])
    first, second = [f.finding_id for f in result.findings[:2]]
    selected_box(page, "notes_finding").select(first).run()
    page.text_area(key=f"note_text_0_{first}").input("<script>literal only</script>")
    page.selectbox(key=f"note_disp_0_{first}").select("suspicious activity")
    page.button(key=f"note_save_0_{first}").click().run()
    assert any("<script>literal only</script>" in item.value for item in page.code)
    assert not any("<script>" in item.value for item in page.markdown)
    selected_box(page, "notes_finding").select(second).run()
    assert page.text_area(key=f"note_text_0_{second}").value == ""
    assert page.selectbox(key=f"note_disp_0_{second}").value == "needs investigation"
    # A new final failure extends the episode, changing its stable finding identity.
    extra = dict(build_scenarios()["suspicious_sequence"][-3], record_id=9998,
                 timestamp="2026-01-15T09:04:30Z")
    page.session_state["imports"].import_files([InputFile("extra.jsonl", render_jsonl([extra]))])
    page.run()
    assert not page.exception
    assert first in page.session_state["finding_notes"]
    assert any("Previous-finding notes" in item.value for item in page.subheader)
    assert first not in [f.finding_id for f in analyze(page.session_state["imports"]).findings]


def test_timezone_assumption_import_manifest_and_errors():
    page = page_for()
    page.selectbox(key="synthetic_dataset").select("edge_cases")
    page.selectbox(key="assumed_tz").select("Asia/Amman")
    page.button(key="import_synthetic").click().run()
    assert not page.exception
    session = page.session_state["imports"]
    assert session.files[0].assumed_timezone == "Asia/Amman"
    assert session.files[0].accepted == 9
    assert session.files[0].rejected == 1
    assert session.files[0].duplicates == 1
    table = next(item.value for item in page.dataframe if "SHA-256" in item.value.columns)
    assert table.iloc[0]["Assumed timezone"] == "Asia/Amman"
    assert table.iloc[0]["SHA-256"] == session.files[0].sha256
    assert "full-case" in page.get("download_button")[0].label


def test_chart_spec_enforces_utc_scope_and_zero_based_volume():
    rows = [{"UTC bin start": "2026-01-15T09:00:00+00:00",
             "UTC bin end": "2026-01-15T09:01:00+00:00", "Distinct events": 1}]
    spec = chart_spec(rows, 60)
    assert spec["encoding"]["x"]["scale"]["type"] == "utc"
    assert "UTC" in spec["encoding"]["x"]["title"]
    assert spec["encoding"]["y"]["scale"]["zero"] is True
    assert spec["data"]["values"][0]["utc_epoch_ms"] == 1768467600000
    assert spec["data"]["values"][0]["Distinct events"] == 1


def test_filtered_timeline_survives_navigation_for_export_and_reset_defaults():
    page = page_for("Timeline", "suspicious_sequence")
    page.multiselect(key="tl_ids").select("4625").run()
    switch(page, "Reports")
    page.button(key="prepare_exports_button").click().run(timeout=30)
    assert not page.exception
    bundle = page.session_state["prepared_exports"]
    assert bundle.snapshot["manifest"]["timeline_exports"]["filtered"]["count"] == 5
    switch(page, "Timeline")
    assert page.multiselect(key="tl_ids").value == ["4625"]
    page.button(key="tl_clear").click().run()
    switch(page, "Reports")
    assert not page.get("download_button")
    page.checkbox(key="include_original_evidence_0").check().run()
    page.checkbox(key="reset_confirm_0").check().run()
    page.button(key="reset_button").click().run()
    switch(page, "Reports")
    assert not page.checkbox(key="include_original_evidence_1").value
    assert not page.get("download_button")


def test_option_changes_replace_widget_identity_without_stale_selected_labels():
    page = page_for("Findings", "suspicious_sequence")
    first_widget = selected_box(page, "fd_selected").key
    page.selectbox(key="fd_rule").select("R3").run()
    current = selected_box(page, "fd_selected")
    assert current.key != first_widget
    assert current.value.startswith("R3-")
    switch(page, "Evidence")
    old_widget = selected_box(page, "ev_event").key
    page.text_input(key="ev_find").input("2026-01-15T09:08").run()
    assert not page.exception
    current = selected_box(page, "ev_event")
    assert current.key != old_widget
    assert page.session_state["imports"].events[current.value].fields["record_id"] == 2107
