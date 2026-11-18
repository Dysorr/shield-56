"""Session-only case notes and complete reset. No shared caches or file storage."""

from datetime import datetime, timezone

from incident_analyzer.ingestion import ImportSession
from incident_analyzer.session import initialize_session

DISPOSITIONS = ("needs investigation", "expected activity", "suspicious activity")
MAX_NOTE_LENGTH = 20000


def ensure_case(state):
    initialize_session(state)
    state.setdefault("imports", ImportSession())
    state.setdefault("case_generation", 0)
    state.setdefault("finding_notes", {})
    state.setdefault("case_conclusion", "")
    state.setdefault("case_disposition", DISPOSITIONS[0])


def uploader_key(state):
    return f"uploads_{state.get('case_generation', 0)}"


def reset_case(state):
    """Use as a button callback, before widgets are constructed on the next run."""
    generation = state.get("case_generation", 0) + 1
    # All this app's session values belong to the case, including widget state.
    state.clear()
    state["case_generation"] = generation
    ensure_case(state)
    state["case_reset_message"] = True


def _validate_note(text, disposition):
    if not isinstance(text, str) or len(text) > MAX_NOTE_LENGTH:
        raise ValueError(f"Notes must be text no longer than {MAX_NOTE_LENGTH:,} characters.")
    if disposition not in DISPOSITIONS:
        raise ValueError("Select one of the listed analyst dispositions.")


def save_finding_note(state, finding, text, disposition):
    _validate_note(text, disposition)
    ensure_case(state)
    state["finding_notes"][finding.finding_id] = {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "rule_version": finding.rule_version,
        "supporting_event_keys": list(finding.supporting_event_keys),
        "note": text,
        "disposition": disposition,
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def save_conclusion(state, text, disposition):
    _validate_note(text, disposition)
    ensure_case(state)
    state["case_conclusion"] = text
    state["case_disposition"] = disposition
    state["case_conclusion_saved_at"] = datetime.now(timezone.utc).isoformat()
