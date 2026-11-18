"""In-process startup checks, not browser end-to-end tests."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_minimal_page_starts_without_exception():
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    page = AppTest.from_file(str(app_path)).run(timeout=20)
    assert not page.exception
    # The accessible brand header may use a styled HTML h1.
    assert "Shield 56" in " ".join(element.value for element in page.markdown) or (
        page.title and page.title[0].value == "Shield 56"
    )
    assert "Available now: import CSV/JSONL" in page.info[0].value
    assert "hypotheses" in page.warning[0].value.lower()
    assert page.session_state["investigation"]["source_records"] == []
    assert len(page.file_uploader) == 0
