"""Native Streamlit UI checks with real detection results, not mock findings."""

from streamlit.testing.v1 import AppTest

from incident_analyzer.ingestion import ImportSession
from incident_analyzer.models import InputFile
from scripts.generate_synthetic import render_csv, render_jsonl
from scripts.synthetic_scenarios import build_scenarios

PAGE = """
import streamlit as st
from incident_analyzer.findings_ui import findings_page
findings_page(st)
"""


def page_for(name="suspicious_sequence", both_formats=False):
    session = ImportSession()
    records = build_scenarios()[name]
    files = [InputFile("sample.jsonl", render_jsonl(records))]
    if both_formats:
        files.append(InputFile("sample.csv", render_csv(records)))
    session.import_files(files)
    page = AppTest.from_string(PAGE)
    page.session_state["imports"] = session
    return page.run(timeout=20)


def test_findings_show_real_results_active_config_and_details():
    page = page_for()
    assert not page.exception
    assert [m.value for m in page.metric] == ["19", "19", "3"]
    assert any('"success_window_minutes": 10' in item.value for item in page.json)
    page.selectbox(key="fd_rule").select("R3").run()
    assert not page.exception
    assert any("Severity: High" in item.value for item in page.text)
    assert any("malicious persistence require further evidence" in item.value for item in page.code)
    assert any("2107" in item.value for item in page.code)


def test_support_table_links_each_event_to_its_own_sources_across_formats():
    page = page_for(both_formats=True)
    page.selectbox(key="fd_rule").select("R3").run()
    assert not page.exception
    support = next(df.value for df in page.dataframe if "Source reference" in df.value.columns)
    assert len(support) == 14
    session = page.session_state["imports"]
    for _, row in support.iterrows():
        event = session.events[row["Event key"]]
        assert row["Record ID"] == event.fields["record_id"]
        assert row["Source reference"] in {o.source_ref for o in event.occurrences}


def test_normal_admin_activity_has_no_findings_without_claiming_safety():
    page = page_for("normal_activity")
    assert not page.exception
    assert page.metric[2].value == "0"
    assert "does not mean the environment is safe" in page.info[0].value


def test_rerun_reimport_and_reset_do_not_leave_stale_results():
    page = page_for()
    session = page.session_state["imports"]
    selected = page.session_state["fd_selected"]
    session.import_files([InputFile("again.jsonl", render_jsonl(build_scenarios()["suspicious_sequence"]))])
    page.run()
    assert not page.exception
    assert [m.value for m in page.metric] == ["19", "38", "3"]
    assert page.session_state["fd_selected"] == selected
    page.session_state["imports"] = ImportSession()
    page.run()
    assert not page.exception
    assert "Import evidence first" in page.info[0].value
    assert not page.metric


def test_no_filter_results_and_evidence_are_safe_plain_text():
    page = page_for()
    page.selectbox(key="fd_rule").select("R1")
    page.selectbox(key="fd_severity").select("High").run()
    assert not page.exception
    assert "No findings match" in page.info[0].value
    records = build_scenarios()["suspicious_sequence"][-7:]
    records[-1]["task_name"] = "<script>alert('SYNTHETIC ONLY')</script>"
    session = ImportSession()
    session.import_files([InputFile("html.jsonl", render_jsonl(records))])
    page = AppTest.from_string(PAGE)
    page.session_state["imports"] = session
    page.run()
    page.selectbox(key="fd_rule").select("R3").run()
    assert not page.exception
    assert any("<script>" in item.value for item in page.code)
    assert not any("<script>" in item.value for item in page.markdown)
