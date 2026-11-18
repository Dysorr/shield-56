"""Shield 56 - Security Incident Timeline Analyzer. Evidence ingestion and timeline."""

import platform
from importlib import metadata

import streamlit as st

from incident_analyzer.branding import (
    APP_NAME,
    render_header,
    render_sidebar_identity,
    render_styles,
)
from incident_analyzer import case_ui
from incident_analyzer.case_state import ensure_case
from incident_analyzer.evidence_ui import evidence_page
from incident_analyzer.findings_ui import findings_page
from incident_analyzer.ingestion_ui import import_page
from incident_analyzer.notes_ui import notes_page
from incident_analyzer.reports_ui import reports_page
from incident_analyzer.session import initialize_session
from incident_analyzer.timeline_ui import timeline_page


def package_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not installed"


st.set_page_config(page_title=APP_NAME, layout="centered")

initialize_session(st.session_state)
ensure_case(st.session_state)
render_styles(st)


def welcome_page() -> None:
    render_header(st)
    st.write("Welcome to Shield 56, a student investigation tool for exported Windows security events.")
    st.info(
        "Available now: import CSV/JSONL exports and Windows XML, validation with source references, "
        "a UTC timeline of distinct events with full source provenance, deterministic findings to investigate, and full-case reports."
    )
    st.subheader("Workflow")
    st.markdown(
        """
1. Import exported Windows security event records (available).
2. Validate records and list any problems found (available).
3. Build an ordered UTC incident timeline (available).
4. Highlight findings worth investigating (available).
5. Inspect original evidence and record analyst notes and a case conclusion (available, session only).
6. Produce a full-case report with Markdown, printable HTML and evidence manifest downloads (available).
"""
    )
    st.warning(
        "Findings are hypotheses "
        "for review, not conclusions; no findings does not mean the environment is safe."
    )


def reports_view_page() -> None:
    render_header(st)
    reports_page(st)


def project_page() -> None:
    render_header(st)
    st.subheader("Privacy and session")
    st.write(
        "Imported evidence is kept only in your current Streamlit session in server "
        "memory. It is not written to disk, shared caches, or other sessions, and it is "
        "lost when the session ends or you reset the case. No external AI API is used. "
        "This is not a browser-only application or a forensic evidence vault."
    )
    st.subheader("Runtime")
    col1, col2 = st.columns(2)
    col1.metric("Python", platform.python_version())
    col2.metric("streamlit", package_version("streamlit"))
    col1.metric("pandas", package_version("pandas"))
    col2.metric("pytest", package_version("pytest"))


def import_evidence_page() -> None:
    render_header(st)
    import_page(st)


def timeline_view_page() -> None:
    render_header(st)
    timeline_page(st)


def findings_view_page() -> None:
    render_header(st)
    findings_page(st)


def evidence_view_page() -> None:
    render_header(st)
    evidence_page(st)


def notes_view_page() -> None:
    render_header(st)
    notes_page(st)


render_sidebar_identity(st)
pages = {
    "welcome": st.Page(welcome_page, title="Welcome", url_path="welcome", default=True),
    "import": st.Page(import_evidence_page, title="Import evidence", url_path="import"),
    "timeline": st.Page(timeline_view_page, title="Timeline", url_path="timeline"),
    "findings": st.Page(findings_view_page, title="Findings", url_path="findings"),
    "evidence": st.Page(evidence_view_page, title="Evidence", url_path="evidence"),
    "notes": st.Page(notes_view_page, title="Analyst notes", url_path="notes"),
    "reports": st.Page(reports_view_page, title="Reports", url_path="reports"),
    "project": st.Page(project_page, title="Project information", url_path="project"),
}
case_ui.register_pages(st.session_state, pages)
nav = st.navigation(list(pages.values()))
case_ui.render_case_reset(st)
case_ui.render_case_notice(st)
nav.run()
