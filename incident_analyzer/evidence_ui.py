"""Evidence page: any distinct full-case event with its original source records."""

from __future__ import annotations

import pandas as pd
from incident_analyzer.widget_state import scoped_selectbox

from incident_analyzer.ingestion_ui import (
    ERRORS_PER_PAGE, event_id_of, get_import_session, page_slice, render_event_detail,
)

EVIDENCE_PER_PAGE = 200


def evidence_label(event) -> str:
    return f"{event.timestamp_utc.isoformat()}  ID {event_id_of(event)}  {event.event_key}"


def render_rejected(st, session) -> None:
    with st.expander(f"Rejected source records ({len(session.errors):,})"):
        if not session.errors:
            st.text("No rejected records.")
            return
        for issue in page_slice(st, list(session.errors), ERRORS_PER_PAGE, "ev_issue_page", "Rejected records"):
            with st.container(border=True):
                st.text(f"{issue.source_ref}  (record {issue.record_position}, lines {issue.line_start}-{issue.line_end})")
                st.text(f"Import {issue.import_id}: {issue.filename}")
                st.text(f"Problem: {issue.message}")
                st.code(issue.source_record, language=None)


def evidence_page(st) -> None:
    session = get_import_session(st.session_state)
    st.subheader("Evidence")
    st.caption("Scope: FULL CASE. Every distinct event with filename, SHA-256, record position, "
               "normalized fields, and the raw original record.")
    events = sorted(session.analysis_events, key=lambda e: (e.timestamp_utc, e.event_key))
    if not events and not session.errors:
        st.info("No evidence yet. Import evidence first, then return to this page.")
        return
    if events:
        by_key = {e.event_key: e for e in events}
        # A cross-view navigation target is a one-shot request, not a widget lock.
        focus = st.session_state.pop("evidence_focus", None)
        if focus is not None and focus not in by_key:
            st.warning("The previously focused event is no longer in this case.")
            st.session_state.pop("evidence_focus", None)
            focus = None
        needle = st.text_input("Find event (key, event ID, or timestamp)", key="ev_find").strip().casefold()
        pool = [e for e in events if not needle or needle in evidence_label(e).casefold()]
        if focus is not None and by_key[focus] not in pool:
            pool = [by_key[focus]] + pool
        st.caption(f"{len(pool):,} of {len(events):,} distinct events")
        if not pool:
            st.info("No events match.")
        else:
            if focus is not None:
                idx = pool.index(by_key[focus])
                st.session_state["ev_page"] = idx // EVIDENCE_PER_PAGE + 1
                st.session_state["ev_event"] = focus
            page = page_slice(st, pool, EVIDENCE_PER_PAGE, "ev_page", "Event list")
            keys = [e.event_key for e in page]
            if st.session_state.get("ev_event") not in keys:
                st.session_state.pop("ev_event", None)
            if focus is not None:
                # A requested focus must also override any existing widget value.
                for widget_key in list(st.session_state):
                    if widget_key.startswith("ev_event__"):
                        del st.session_state[widget_key]
            chosen = scoped_selectbox(st, "Event", keys, format_func=lambda k: evidence_label(by_key[k]), key="ev_event")
            event = by_key[chosen]
            st.dataframe(pd.DataFrame([{
                "Filename": o.filename, "SHA-256": o.file_sha256, "Record position": o.record_position,
                "Lines": f"{o.line_start}-{o.line_end}", "Source reference": o.source_ref,
            } for o in event.occurrences]), hide_index=True, width="stretch")
            render_event_detail(st, event)
    else:
        st.info("No accepted events. Rejected records are listed below.")
    render_rejected(st, session)
