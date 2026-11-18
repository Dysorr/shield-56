"""Protect session isolation and investigation preservation across reruns."""

from incident_analyzer.session import initialize_session


def test_initializes_empty_investigation():
    state = {}
    initialize_session(state)
    assert state["investigation"] == {
        "source_records": [],
        "validation_errors": [],
        "findings": [],
        "analyst_notes": "",
        "conclusions": "",
    }


def test_rerun_preserves_existing_investigation():
    state = {}
    initialize_session(state)
    investigation = state["investigation"]
    investigation["analyst_notes"] = "Check the source event before concluding."
    investigation["source_records"].append({"synthetic": True})
    initialize_session(state)
    assert state["investigation"] is investigation
    assert len(investigation["source_records"]) == 1
    assert investigation["analyst_notes"] == "Check the source event before concluding."


def test_sessions_do_not_share_mutable_containers():
    first, second = {}, {}
    initialize_session(first)
    initialize_session(second)
    for key in ("source_records", "validation_errors", "findings"):
        first["investigation"][key].append("synthetic test marker")
        assert second["investigation"][key] == []
        assert first["investigation"][key] is not second["investigation"][key]


def test_preserves_unrelated_session_state():
    state = {"navigation": "Overview"}
    initialize_session(state)
    assert state["navigation"] == "Overview"
