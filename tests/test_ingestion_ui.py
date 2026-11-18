"""In-process integration checks over the real Streamlit controls and session."""

from streamlit.testing.v1 import AppTest

from incident_analyzer.ingestion import ImportSession
from incident_analyzer.ingestion_ui import (
    NO_TIMEZONE, filter_events, get_import_session, precheck_uploads, synthetic_path,
)
from incident_analyzer.models import InputFile
from scripts.generate_synthetic import render_jsonl
from scripts.synthetic_scenarios import build_scenarios

IMPORT_PAGE = """
import streamlit as st
from incident_analyzer.ingestion_ui import import_page
from incident_analyzer.case_ui import render_case_reset
render_case_reset(st)
import_page(st)
"""
TIMELINE_PAGE = """
import streamlit as st
from incident_analyzer.ingestion_ui import timeline_page
timeline_page(st)
"""


def test_sample_import_reimport_and_confirmed_reset():
    page = AppTest.from_string(IMPORT_PAGE).run()
    assert not page.exception
    assert page.selectbox(key="assumed_tz").value == NO_TIMEZONE
    assert page.button(key="import_uploads").disabled
    page.selectbox(key="synthetic_dataset").select("edge_cases")
    page.button(key="import_synthetic").click().run()
    assert not page.exception
    session = page.session_state["imports"]
    assert session.total_records == 10
    assert len(session.events) == 7
    assert len(session.errors) == 2
    assert session.files[0].duplicates == 1
    assert page.button(key="reset_button").disabled
    page.run()  # A rerun is not a repeated import.
    assert len(page.session_state["imports"].files) == 1
    page.selectbox(key="synthetic_format").select("JSONL")
    page.button(key="import_synthetic").click().run()
    assert not page.exception
    session = page.session_state["imports"]
    assert len(session.events) == 7
    assert session.files[-1].duplicates == 8
    assert sum(len(event.occurrences) for event in session.events.values()) == 16
    page.checkbox(key="reset_confirm_0").check().run()
    page.button(key="reset_button").click().run()
    assert not page.exception
    assert page.session_state["imports"].total_bytes == 0
    assert not page.session_state["imports"].events


def test_timeline_includes_unknown_id_and_safe_raw_html():
    session = ImportSession()
    records = build_scenarios()["edge_cases"]
    session.import_files([InputFile("edge.jsonl", render_jsonl(records))])
    page = AppTest.from_string(TIMELINE_PAGE)
    page.session_state["imports"] = session
    page.run()
    assert not page.exception
    assert "65000" in page.multiselect(key="tl_ids").options
    page.multiselect(key="tl_ids").select("4698").run()
    assert not page.exception
    assert any("<script>" in element.value for element in page.code)
    assert not any("<script>" in element.value for element in page.markdown)
    assert len(page.session_state["imports"].events) == 7
    page.text_input(key="tl_search").input("nothing-matches-this").run()
    assert not page.exception
    assert any("No events match" in info.value for info in page.info)


def test_filter_uses_normalized_keys_without_mutating_evidence():
    session = ImportSession()
    session.import_files([InputFile("events.jsonl", render_jsonl(build_scenarios()["suspicious_sequence"]))])
    events = session.analysis_events
    filtered = filter_events(events, "ALICE", ["4698"])
    assert len(filtered) == 1
    assert filtered[0].fields["subject_user"] == "alice"
    assert len(session.events) == 19


def test_session_initializer_and_synthetic_paths_are_isolated():
    first, second = {}, {}
    assert get_import_session(first) is get_import_session(first)
    assert get_import_session(first) is not get_import_session(second)
    import pytest
    with pytest.raises(ValueError):
        synthetic_path("../evaluation", "jsonl")


def test_precheck_rejects_oversize_before_calling_getvalue():
    class UnreadUpload:
        size = 10_000_001

        def getvalue(self):
            raise AssertionError("must not read oversized upload")

    assert "per-file" in precheck_uploads([UnreadUpload()], ImportSession())
