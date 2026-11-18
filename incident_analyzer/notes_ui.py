"""Analyst notes and case conclusion. Kept in session memory only, shown as literal text."""

from __future__ import annotations

from incident_analyzer.case_state import (
    DISPOSITIONS, MAX_NOTE_LENGTH, ensure_case, save_conclusion, save_finding_note,
)
from incident_analyzer.findings_ui import finding_label, run_analysis
from incident_analyzer.ingestion_ui import get_import_session
from incident_analyzer.widget_state import scoped_selectbox


def _drafts(state) -> dict:
    return state.setdefault("note_drafts", {})


def _copy_draft(state, widget_key: str, draft_key: str) -> None:
    _drafts(state)[draft_key] = state.get(widget_key)


def _seed(state, widget_key: str, draft_key: str, saved) -> None:
    if widget_key not in state:
        draft = _drafts(state).get(draft_key)
        state[widget_key] = saved if draft is None else draft


def _save_note(state, finding, text_key, disp_key) -> None:
    try:
        save_finding_note(state, finding, state.get(text_key, ""), state.get(disp_key))
        state["notes_message"] = ("success", f"Note saved in this session for {finding.finding_id}.")
    except ValueError as exc:
        state["notes_message"] = ("error", str(exc))


def _save_conclusion(state, text_key, disp_key) -> None:
    try:
        save_conclusion(state, state.get(text_key, ""), state.get(disp_key))
        state["notes_message"] = ("success", "Case conclusion saved in this session.")
    except ValueError as exc:
        state["notes_message"] = ("error", str(exc))


def render_saved(st, record: dict) -> None:
    st.text(f"Saved at (UTC): {record['saved_at_utc']}  Disposition: {record['disposition']}")
    st.text(f"Rule: {record['rule_id']} {record['rule_name']} (version {record['rule_version']})")
    st.text("Saved note (literal text):")
    st.code(record["note"] or "(empty)", language=None)


def render_finding_notes(st, findings) -> None:
    state = st.session_state
    gen = state.get("case_generation", 0)
    st.subheader("Finding notes")
    st.caption("Scope: FULL CASE findings. Notes are tied to the stable finding ID.")
    if not findings:
        st.info("No current findings to annotate. The case conclusion below is always available.")
        return
    by_id = {f.finding_id: f for f in findings}
    ids = list(by_id)
    if state.get("selected_finding_id") in by_id:
        state.setdefault("notes_finding", state["selected_finding_id"])
    if state.get("notes_finding") not in by_id:
        state.pop("notes_finding", None)
    fid = scoped_selectbox(st, "Finding", ids, format_func=lambda i: finding_label(by_id[i]), key="notes_finding")
    state["selected_finding_id"] = fid
    finding = by_id[fid]
    saved = state["finding_notes"].get(fid)
    text_key, disp_key = f"note_text_{gen}_{fid}", f"note_disp_{gen}_{fid}"
    _seed(state, text_key, f"text:{fid}", saved["note"] if saved else "")
    _seed(state, disp_key, f"disp:{fid}", saved["disposition"] if saved else DISPOSITIONS[0])
    st.selectbox("Disposition", DISPOSITIONS, key=disp_key,
                 on_change=_copy_draft, args=(state, disp_key, f"disp:{fid}"))
    st.text_area("Analyst note", key=text_key, max_chars=MAX_NOTE_LENGTH, height=200,
                 on_change=_copy_draft, args=(state, text_key, f"text:{fid}"))
    st.button("Save note", type="primary", key=f"note_save_{gen}_{fid}",
              on_click=_save_note, args=(state, finding, text_key, disp_key))
    if saved:
        render_saved(st, saved)
    else:
        st.caption("Not saved yet.")


def render_orphans(st, current_ids) -> None:
    orphans = {k: v for k, v in st.session_state["finding_notes"].items() if k not in current_ids}
    if not orphans:
        return
    st.subheader("Previous-finding notes (not current)")
    st.warning("These finding IDs are not produced by the current evidence. Their notes are kept "
               "here and are not attached to any current finding.")
    for fid, record in orphans.items():
        with st.expander(f"Previous finding {fid}"):
            render_saved(st, record)
            st.text(f"Supporting event keys at save time: {len(record['supporting_event_keys']):,}")


def render_conclusion(st) -> None:
    state = st.session_state
    gen = state.get("case_generation", 0)
    st.subheader("Case conclusion")
    text_key, disp_key = f"conclusion_text_{gen}", f"conclusion_disp_{gen}"
    _seed(state, text_key, "conclusion:text", state["case_conclusion"])
    _seed(state, disp_key, "conclusion:disp", state["case_disposition"])
    st.selectbox("Case disposition", DISPOSITIONS, key=disp_key,
                 on_change=_copy_draft, args=(state, disp_key, "conclusion:disp"))
    st.text_area("Conclusion", key=text_key, max_chars=MAX_NOTE_LENGTH, height=200,
                 on_change=_copy_draft, args=(state, text_key, "conclusion:text"))
    st.button("Save conclusion", type="primary", key=f"conclusion_save_{gen}",
              on_click=_save_conclusion, args=(state, text_key, disp_key))
    saved_at = state.get("case_conclusion_saved_at")
    if saved_at:
        st.text(f"Saved at (UTC): {saved_at}  Disposition: {state['case_disposition']}")
        st.text("Saved conclusion (literal text):")
        st.code(state["case_conclusion"] or "(empty)", language=None)
    else:
        st.caption("Not saved yet.")


def notes_page(st) -> None:
    ensure_case(st.session_state)
    st.subheader("Analyst notes")
    st.warning("Save stores text only in this session's memory. Refreshing or ending the session "
               "loses unsaved and saved work. Findings are hypotheses, not conclusions.")
    message = st.session_state.pop("notes_message", None)
    if message:
        (st.error if message[0] == "error" else st.success)(message[1])
    session = get_import_session(st.session_state)
    findings = list(run_analysis(st.session_state).findings) if session.events else []
    if not session.events:
        st.info("No evidence imported yet. You can still record a case conclusion.")
    render_finding_notes(st, findings)
    render_orphans(st, {f.finding_id for f in findings})
    st.divider()
    render_conclusion(st)
