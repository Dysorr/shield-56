"""Analyst judgment editor. Saved values live only in session state; drafts are never reported."""

from __future__ import annotations

from copy import deepcopy

from incident_analyzer.report_context import default_judgments, save_judgments

MAX_CHARS = 20000
STATUSES = ("proposed", "performed")
STATUS_LABELS = {
    "proposed": "Proposed (not performed)",
    "performed": "Performed (analyst-recorded, not independently verified)",
}
ACTION_TITLES = {"containment": "Containment action", "recovery": "Recovery action"}


def current_judgments(state) -> dict:
    return deepcopy(state.get("report_judgments") or default_judgments())


def render_judgments(st) -> None:
    state = st.session_state
    saved = current_judgments(state)
    st.subheader("Analyst judgments")
    st.caption(
        "Your interpretation, kept separate from original event evidence. Only saved values "
        "enter reports and exports; unsaved drafts are excluded. This tool never executes actions."
    )
    if saved.get("saved_at_utc"):
        st.text(f"Last saved (UTC): {saved['saved_at_utc']}")
    else:
        st.info("Not saved yet. Reports use the default title and proposed actions until you save.")

    generation = state.get("case_generation", 0)
    with st.form(f"analyst_judgments_form_{generation}"):
        title = st.text_input("Case title", value=saved["case_title"], max_chars=MAX_CHARS)
        observations = st.text_area(
            "Observations (what the evidence shows)", value=saved["observations"], max_chars=MAX_CHARS)
        hypotheses = st.text_area(
            "Hypotheses (what may explain it)", value=saved["hypotheses"], max_chars=MAX_CHARS)
        alternatives = st.text_area(
            "Alternative explanations", value=saved["alternative_explanations"], max_chars=MAX_CHARS)
        actions = []
        for index, action in enumerate(saved["actions"]):
            category = action["category"]
            st.markdown(f"**{ACTION_TITLES.get(category, category.title())}**")
            description = st.text_area(
                "Description", value=action["description"], max_chars=MAX_CHARS,
                key=f"judgment_action_{generation}_{index}_description")
            status = st.radio(
                "Status", STATUSES, index=STATUSES.index(action.get("status", "proposed")),
                format_func=STATUS_LABELS.get, horizontal=True, key=f"judgment_action_{generation}_{index}_status")
            record = st.text_area(
                "Performed record (required if performed): who performed it, when, and the evidence of completion",
                value=action.get("performed_record", ""), max_chars=MAX_CHARS,
                key=f"judgment_action_{generation}_{index}_record")
            if action.get("status") == "performed" and action.get("performed_at_utc"):
                st.caption(f"Recorded as performed (UTC): when the analyst saved this record, not proof of when the action occurred: {action['performed_at_utc']}")
            actions.append({"category": category, "description": description, "status": status,
                            "performed_at_utc": action.get("performed_at_utc"),
                            "performed_record": record})
        st.caption(
            "'Performed' is an analyst-recorded statement only; it is not independently verified. "
            "Its timestamp marks when the analyst recorded it as performed, not proof of the actual action time."
        )
        submitted = st.form_submit_button("Save analyst judgments")

    if submitted:
        values = {"case_title": title, "observations": observations, "hypotheses": hypotheses,
                  "alternative_explanations": alternatives, "actions": actions}
        try:
            save_judgments(state, values)
        except ValueError as exc:
            st.error(f"Analyst judgments were not saved: {exc}")
        else:
            st.success("Analyst judgments saved. Any prepared exports are now out of date.")
