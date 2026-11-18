"""Initialize investigation state without sharing mutable data between sessions."""

from collections.abc import MutableMapping
from typing import Any


def initialize_session(state: MutableMapping[str, Any]) -> None:
    """Set up a fresh investigation once; preserve it across Streamlit reruns."""
    if "investigation" not in state:
        state["investigation"] = {
            "source_records": [],
            "validation_errors": [],
            "findings": [],
            "analyst_notes": "",
            "conclusions": "",
        }
