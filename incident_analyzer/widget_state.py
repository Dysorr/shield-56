"""Keep selectbox labels aligned with options in Streamlit's keyed widget lifecycle."""

from hashlib import sha256
import json


def scoped_selectbox(st, label, options, *, key, format_func=str):
    """A changed option list gets a fresh browser widget, preserving valid selection."""
    options = list(options)
    signature = sha256(json.dumps(options, ensure_ascii=False).encode()).hexdigest()[:16]
    widget_key = f"{key}__{st.session_state.get('case_generation', 0)}_{signature}"
    selected = st.session_state.get(key)
    index = options.index(selected) if selected in options else 0
    value = st.selectbox(label, options, index=index, format_func=format_func, key=widget_key)
    st.session_state[key] = value  # Persistent selection, not owned by widget cleanup.
    return value
