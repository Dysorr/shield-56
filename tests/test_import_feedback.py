from streamlit.testing.v1 import AppTest


def test_all_rejected_file_is_warning_not_misleading_success():
    page = AppTest.from_string("""
import streamlit as st
from incident_analyzer.ingestion_ui import run_import, render_import_message
from incident_analyzer.models import InputFile
if st.button("Import invalid"):
    run_import(st, [InputFile("invalid.jsonl", b'{"event_id":4624}\\n')], None)
render_import_message(st)
""").run()
    page.button[0].click().run()
    assert not page.exception
    assert not page.success
    assert "Accepted 0 occurrence(s), rejected 1 record(s)" in page.warning[0].value
