"""Filtered timeline view. Filters affect display only; analysis always uses the full case."""

from __future__ import annotations

import pandas as pd
from datetime import datetime
from incident_analyzer.widget_state import scoped_selectbox

from incident_analyzer.case_ui import go_to
from incident_analyzer.ingestion_ui import (
    EVENTS_PER_PAGE, event_id_of, event_row, get_import_session, page_slice, render_event_detail,
)
from incident_analyzer.timeline_filters import account_label, filter_timeline, volume_bins

CHART_COLOR = "#61A9BD"
FILTER_KEYS = ("tl_start", "tl_end", "tl_hosts", "tl_accounts", "tl_ids", "tl_ips", "tl_search", "tl_page", "tl_event")


def missing_label(value) -> str:
    return "(missing)" if value is None else str(value)


def clear_filters(state) -> None:
    for key in [k for k in list(state.keys()) if str(k).startswith("tl_")]:
        del state[key]
    state["timeline_display_filters"] = {}


def chronological(events) -> list:
    return sorted(events, key=lambda e: (e.timestamp_utc, e.event_key))


def chart_spec(rows: list, width_seconds: int) -> dict:
    single = len(rows) == 1
    x = {"field": "utc_epoch_ms", "type": "temporal", "title": "UTC time (bin start)",
         "scale": {"type": "utc"}, "axis": {"format": "%Y-%m-%d %H:%M"}}
    y = {"field": "Distinct events", "type": "quantitative", "title": "Distinct events",
         "scale": {"zero": True}, "axis": {"tickMinStep": 1}}
    tooltip = [
        {"field": "UTC bin start", "type": "nominal", "title": "UTC bin start"},
        {"field": "UTC bin end", "type": "nominal", "title": "UTC bin end"},
        {"field": "Distinct events", "type": "quantitative", "title": "Distinct events"},
    ]
    mark = ({"type": "line", "point": {"filled": True, "size": 80}, "color": CHART_COLOR} if single
            else {"type": "area", "color": CHART_COLOR, "opacity": 0.75, "line": {"color": CHART_COLOR}})
    # Numeric epoch milliseconds avoid browser/Arrow string-date parsing differences.
    chart_rows = [
        dict(row, utc_epoch_ms=datetime.fromisoformat(row["UTC bin start"]).timestamp() * 1000)
        for row in rows
    ]
    return {"data": {"values": chart_rows}, "mark": mark,
            "encoding": {"x": x, "y": y, "tooltip": tooltip}, "height": 220}


def render_volume_chart(st, shown) -> None:
    rows, width = volume_bins(shown)
    if not rows:
        return
    st.caption("Event volume (filtered timeline)")
    st.vega_lite_chart(spec=chart_spec(rows, width), width="stretch")
    minutes = width // 60
    st.caption(
        f"Scope: FILTERED TIMELINE, full filtered range {rows[0]['UTC bin start']} to "
        f"{rows[-1]['UTC bin end']} in {len(rows)} bin(s) of {minutes} minute(s). "
        "A zero bin means no imported events in that interval, not proof of inactivity."
    )


def timeline_page(st) -> None:
    session = get_import_session(st.session_state)
    st.subheader("Timeline (UTC)")
    events = chronological(session.analysis_events)
    if not events:
        st.info("No events yet. Import evidence first, then return to this page.")
        return
    st.caption("All distinct normalized events, including unrecognized event IDs. Review rule results on Findings.")
    saved = st.session_state.get("timeline_display_filters", {})
    for widget_key, field in (
        ("tl_start", "start_date"), ("tl_end", "end_date"), ("tl_hosts", "hosts"),
        ("tl_accounts", "accounts"), ("tl_ids", "event_ids"), ("tl_ips", "source_ips"),
        ("tl_search", "query"),
    ):
        if widget_key not in st.session_state and field in saved:
            st.session_state[widget_key] = saved[field]

    col1, col2 = st.columns(2)
    start = col1.date_input("UTC start date", value=None, key="tl_start")
    end = col2.date_input("UTC end date", value=None, key="tl_end")
    hosts = col1.multiselect("Hostname", sorted({e.fields.get("hostname") for e in events}, key=missing_label),
                             format_func=missing_label, key="tl_hosts")
    accounts = col2.multiselect("Account", sorted({account_label(e) for e in events}), key="tl_accounts")
    ids = col1.multiselect("Event IDs", sorted({event_id_of(e) for e in events}), key="tl_ids")
    ips = col2.multiselect("Source IP", sorted({e.fields.get("source_ip") for e in events}, key=missing_label),
                           format_func=missing_label, key="tl_ips")
    query = st.text_input("Search fields", key="tl_search")
    st.session_state["timeline_display_filters"] = dict(
        start_date=start, end_date=end, hosts=hosts, accounts=accounts,
        event_ids=ids, source_ips=ips, query=query or "",
    )
    st.button("Clear filters", key="tl_clear", on_click=clear_filters, args=(st.session_state,))

    try:
        shown = filter_timeline(events, start_date=start, end_date=end, hosts=hosts, accounts=accounts,
                                event_ids=ids, source_ips=ips, query=query or "")
    except ValueError as exc:
        st.error(str(exc))
        return
    cols = st.columns(2)
    cols[0].metric("Full-case distinct events", f"{len(events):,}")
    cols[1].metric("Filtered events", f"{len(shown):,}")
    st.caption("Scope: FILTERED TIMELINE. Findings always analyze the full case; these filters are display only.")
    st.caption(f"Showing {len(shown):,} of {len(events):,} distinct events")
    if not shown:
        st.info("No events match the filters. Clear filters to see the full case.")
        return
    render_volume_chart(st, shown)
    page = page_slice(st, shown, EVENTS_PER_PAGE, "tl_page", "Events")
    st.dataframe(pd.DataFrame([event_row(e) for e in page]), hide_index=True, width="stretch")
    labels = {e.event_key: f"{e.timestamp_utc.isoformat()}  ID {event_id_of(e)}  {e.event_key}" for e in page}
    if st.session_state.get("tl_event") not in labels:
        st.session_state.pop("tl_event", None)
    key = scoped_selectbox(st, "Inspect event", list(labels), format_func=labels.get, key="tl_event")
    if st.button("Open on Evidence page", key="tl_open_evidence"):
        st.session_state["evidence_focus"] = key
        go_to(st, "evidence")
    selected = next(e for e in page if e.event_key == key)
    render_event_detail(st, selected)
