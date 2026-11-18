"""Streamlit Findings page. Recomputed from the current ImportSession on every rerun.

All imported or derived strings are rendered as plain text, code, JSON, or dataframes only.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from incident_analyzer.detection import analyze
from incident_analyzer.finding_models import AnalysisResult, Finding
from incident_analyzer.case_ui import go_to
from incident_analyzer.ingestion_ui import get_import_session, page_slice, render_event_detail, render_occurrence
from incident_analyzer.rule_config import DEFAULT_CONFIG
from incident_analyzer.widget_state import scoped_selectbox

ALL = "All"
KEYS_PER_PAGE = 50
FINDING_OCCURRENCES_PER_PAGE = 10

RULE_DESCRIPTIONS = (
    ("R1", "Repeated failed logons",
     "Inclusive rolling windows of at least failure_threshold distinct failures, grouped "
     "by host, target domain/user and source IP (not logon type). Windows sharing evidence "
     "form an episode whose full span may exceed failure_window_minutes."),
    ("R2", "Successful logon following repeated failures",
     "The earliest compatible successful logon strictly after an episode's final failure, "
     "within success_window_minutes, with a compatible logon type. At most one success per "
     "episode; if several compatible episodes qualify, assign to the nearest one. "
     "The success type must equal the known final failure type; tied final types must agree."),
    ("R3", "Task creation following suspicious authentication",
     "A scheduled task created strictly after the chosen R2 success, within "
     "task_window_minutes, on the same host and account, with matching nonzero session IDs "
     "and no visible intervening reuse. All qualifying tasks form one finding per success."),
)


def run_analysis(state) -> AnalysisResult:
    """Always analyze the current session; nothing is cached or stored."""
    return analyze(get_import_session(state), config=DEFAULT_CONFIG)


def text(value: Any) -> str:
    return "none" if value is None or value == "" else str(value)


def finding_label(f: Finding) -> str:
    return f"{f.first_utc.isoformat()}  {f.rule_id}  severity {f.severity}  {f.finding_id}"


def finding_row(f: Finding) -> dict[str, Any]:
    return {
        "Finding ID": f.finding_id,
        "Rule": f"{f.rule_id} {f.rule_name}",
        "Severity": str(f.severity),
        "First (UTC)": f.first_utc.isoformat(),
        "Last (UTC)": f.last_utc.isoformat(),
        "Host": text(f.hostname),
        "Account": text(f.account),
        "Source IP": text(f.source_ip),
        "Events": len(f.supporting_event_keys),
        "Occurrences": len(f.source_occurrences),
    }


def render_summary(st, result: AnalysisResult) -> None:
    cols = st.columns(3)
    cols[0].metric("Distinct events analyzed", f"{result.distinct_events:,}")
    cols[1].metric("Source occurrences", f"{result.source_occurrences:,}")
    cols[2].metric("Findings", len(result.findings))
    counts = {}
    for f in result.findings:
        counts[(f.rule_id, str(f.severity))] = counts.get((f.rule_id, str(f.severity)), 0) + 1
    if counts:
        st.caption("Findings by rule and severity")
        st.dataframe(
            pd.DataFrame([{"Rule": r, "Severity": s, "Count": n} for (r, s), n in sorted(counts.items())]),
            hide_index=True, width="stretch",
        )


def render_method(st, result: AnalysisResult) -> None:
    with st.expander("Rules, active configuration, and exclusions"):
        st.caption("Rule definitions (threshold values are taken from the active configuration below):")
        st.dataframe(
            pd.DataFrame([
                {"Rule": rid, "Version": text(result.rule_versions.get(rid)), "Name": name, "Logic": logic}
                for rid, name, logic in RULE_DESCRIPTIONS
            ]),
            hide_index=True, width="stretch",
        )
        st.caption("Active configuration recorded with this analysis:")
        st.json({str(k): v for k, v in result.configuration.items()})
        st.caption("Rule versions:")
        st.json({str(k): str(v) for k, v in result.rule_versions.items()})
        st.caption("Events excluded from rules because required fields were missing:")
        if result.exclusions:
            st.dataframe(
                pd.DataFrame([{"Reason": str(k), "Count": int(v)} for k, v in result.exclusions.items()]),
                hide_index=True, width="stretch",
            )
        else:
            st.text("No exclusions recorded.")


def render_text_list(st, title: str, items) -> None:
    st.text(f"{title}:")
    if items:
        st.code("\n".join(f"- {i}" for i in items), language=None)
    else:
        st.text("  none")


def render_finding_detail(st, f: Finding, by_id: dict[str, Finding]) -> None:
    st.subheader("Selected finding")
    st.text(f"Finding ID: {f.finding_id}")
    st.text(f"Rule: {f.rule_id} {f.rule_name} (version {f.rule_version})")
    st.text(f"Severity: {f.severity}")
    st.text(f"Window (UTC): {f.first_utc.isoformat()} to {f.last_utc.isoformat()}")
    st.text(f"Host: {text(f.hostname)}  Account: {text(f.account)}  Source IP: {text(f.source_ip)}")
    st.text("Explanation:")
    st.code(f.explanation, language=None)
    st.text("Severity rationale:")
    st.code(f.severity_rationale, language=None)
    render_text_list(st, "Possible benign explanations", f.benign_explanations)
    render_text_list(st, "Analyst checks", f.analyst_checks)
    st.text("Related findings:")
    if f.related_finding_ids:
        st.dataframe(
            pd.DataFrame([
                {"Finding ID": rid,
                 "Rule": f"{by_id[rid].rule_id} {by_id[rid].rule_name}" if rid in by_id else "not in current result"}
                for rid in f.related_finding_ids
            ]),
            hide_index=True, width="stretch",
        )
    else:
        st.text("  none")

    st.caption(f"Supporting events: {len(f.supporting_event_keys):,}")
    rows = [
        {"Event key": event.event_key, "Event ID": event.event_id,
         "Record ID": event.record_id, "Timestamp (UTC)": event.timestamp_utc.isoformat(),
         "Source reference": reference}
        for event in f.supporting_events for reference in event.source_references
    ]
    st.dataframe(
        pd.DataFrame(page_slice(st, rows, KEYS_PER_PAGE, "fd_keys_page", "Supporting events")),
        hide_index=True, width="stretch",
    )

    st.caption(f"Source provenance: {len(f.source_occurrences):,} occurrence(s)")
    for occ in page_slice(st, list(f.source_occurrences), FINDING_OCCURRENCES_PER_PAGE, "fd_occ_page", "Finding occurrences"):
        render_occurrence(st, occ)


def render_evidence_context(st, f: Finding) -> None:
    st.subheader("Supporting evidence context")
    session = get_import_session(st.session_state)
    events = {e.event_key: e for e in session.analysis_events}
    keys = [k for k in f.supporting_event_keys if k in events]
    if not keys:
        st.info("No supporting events are available in the current session.")
        return
    if st.session_state.get("fd_evidence") not in keys:
        st.session_state.pop("fd_evidence", None)
    key = scoped_selectbox(st,
        "Supporting event", keys, key="fd_evidence",
        format_func=lambda k: f"{events[k].timestamp_utc.isoformat()}  {k}",
    )
    col1, col2 = st.columns(2)
    if col1.button("Open on Evidence page", key="fd_open_evidence"):
        st.session_state["evidence_focus"] = key
        go_to(st, "evidence")
    if col2.button("Write a note for this finding", key="fd_open_notes"):
        go_to(st, "notes")
    with st.expander("Normalized fields and original records", expanded=False):
        render_event_detail(st, events[key])


def findings_page(st) -> None:
    st.subheader("Findings")
    st.caption(
        "Deterministic rules applied to the current imported evidence. Findings are hypotheses "
        "to investigate, such as repeated failed logons or task creation following suspicious "
        "authentication. They do not establish compromise or malicious persistence; that "
        "requires further evidence and analyst review."
    )
    st.caption("Scope: FULL CASE. Timeline filters never change analysis; the selectors below only filter this list.")
    session = get_import_session(st.session_state)
    if not session.events:
        st.info("No events yet. Import evidence first, then return to this page.")
        return
    result = run_analysis(st.session_state)
    render_summary(st, result)
    render_method(st, result)
    findings = list(result.findings)
    if not findings:
        st.info(
            "No findings were produced by the current rules and configuration. This does not mean "
            "the environment is safe: activity may fall outside these rules, be missing from the "
            "export, or be excluded because of missing fields."
        )
        return

    col1, col2 = st.columns(2)
    rules = sorted({f.rule_id for f in findings})
    severities = sorted({str(f.severity) for f in findings})
    rule = col1.selectbox("Rule", [ALL] + rules, key="fd_rule")
    sev = col2.selectbox("Severity", [ALL] + severities, key="fd_severity")
    shown = [f for f in findings if (rule == ALL or f.rule_id == rule) and (sev == ALL or str(f.severity) == sev)]
    st.caption(f"Showing {len(shown):,} of {len(findings):,} findings")
    if not shown:
        st.info("No findings match the filters.")
        return
    st.dataframe(pd.DataFrame([finding_row(f) for f in shown]), hide_index=True, width="stretch")
    labels = {f.finding_id: finding_label(f) for f in shown}
    if st.session_state.get("fd_selected") not in labels:
        st.session_state.pop("fd_selected", None)
        if st.session_state.get("selected_finding_id") in labels:
            st.session_state["fd_selected"] = st.session_state["selected_finding_id"]
    chosen = scoped_selectbox(st, "Inspect finding", list(labels), format_func=labels.get, key="fd_selected")
    if st.session_state.get("fd_last_selected") != chosen:
        st.session_state["fd_last_selected"] = chosen
        st.session_state.pop("fd_keys_page", None)
        st.session_state.pop("fd_occ_page", None)
    st.session_state["selected_finding_id"] = chosen
    by_id = {f.finding_id: f for f in findings}
    render_evidence_context(st, by_id[chosen])
    render_finding_detail(st, by_id[chosen], by_id)
