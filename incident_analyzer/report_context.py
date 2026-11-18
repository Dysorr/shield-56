"""Editable analyst assertions and explicitly proposed response actions."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tomllib

APPLICATION_VERSION = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
PROPOSED_ACTIONS = (
    ("containment", "Validate account and host ownership before taking disruptive action; if authorized and justified, isolate affected hosts and revoke suspicious sessions."),
    ("recovery", "Preserve evidence, review unauthorized tasks, rotate affected credentials if warranted, and restore verified configuration after approval."),
)


def default_judgments():
    return {
        "case_title": "Untitled investigation",
        "observations": "", "hypotheses": "", "alternative_explanations": "",
        "actions": [
            {"category": category, "description": text, "status": "proposed",
             "performed_at_utc": None, "performed_record": ""}
            for category, text in PROPOSED_ACTIONS
        ],
        "saved_at_utc": None,
    }


def save_judgments(state, values):
    value = deepcopy(values)
    for key in ("case_title", "observations", "hypotheses", "alternative_explanations"):
        if not isinstance(value.get(key), str) or len(value[key]) > 20000:
            raise ValueError(f"{key} must be text with at most 20,000 characters.")
    if not value["case_title"].strip():
        raise ValueError("Enter a case title.")
    if len(value.get("actions", [])) != 2:
        raise ValueError("Record one containment and one recovery action.")
    now = datetime.now(timezone.utc).isoformat()
    previous = state.get("report_judgments", default_judgments())
    for index, action in enumerate(value["actions"]):
        if action.get("category") != PROPOSED_ACTIONS[index][0]:
            raise ValueError("Unexpected action category.")
        if action.get("status") not in ("proposed", "performed"):
            raise ValueError("Action status must be proposed or performed.")
        for field in ("description", "performed_record"):
            if not isinstance(action.get(field), str) or len(action[field]) > 20000:
                raise ValueError("Action text must be at most 20,000 characters.")
        if action["status"] == "performed" and not action["performed_record"].strip():
            raise ValueError("Describe who performed the action, when, and the evidence of completion.")
        old = previous["actions"][index]
        action["performed_at_utc"] = (
            old.get("performed_at_utc") if old == action else now
        ) if action["status"] == "performed" else None
    value["saved_at_utc"] = now
    state["report_judgments"] = value
