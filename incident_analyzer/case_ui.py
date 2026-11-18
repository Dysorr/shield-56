"""Case-wide notice, reset, and navigation registry. Session-only; nothing is written to disk."""

from __future__ import annotations

from incident_analyzer.case_state import ensure_case, reset_case

def register_pages(state, pages: dict) -> None:
    """app.py registers st.Page objects by url path so views can switch pages."""
    state["_case_pages"] = pages


def go_to(st, url_path: str) -> None:
    page = st.session_state.get("_case_pages", {}).get(url_path)
    if page is not None:
        st.switch_page(page)
    else:
        st.info("Open the requested view from the application navigation.")


def render_case_notice(st) -> None:
    ensure_case(st.session_state)
    if st.session_state.pop("case_reset_message", False):
        st.success("Case reset. All evidence, notes, conclusion, and uploads were cleared from this session.")
    st.caption(
        "Session only: refreshing the browser or ending the session loses unsaved and "
        "session-saved work. Save keeps text in this session's memory; it is not disk persistence."
    )


def render_case_reset(st) -> None:
    ensure_case(st.session_state)
    sidebar = st.sidebar
    sidebar.divider()
    sidebar.caption("Reset case")
    confirmed = sidebar.checkbox(
        "I understand all evidence, notes, conclusion, and uploads will be lost",
        key=f"reset_confirm_{st.session_state['case_generation']}",
    )
    sidebar.button(
        "Reset entire case", disabled=not confirmed, key="reset_button",
        on_click=reset_case, args=(st.session_state,),
    )
