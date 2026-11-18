"""Streamlit ingestion and timeline pages. Evidence is rendered only as text, code, or dataframes."""

from __future__ import annotations

import zoneinfo
from pathlib import Path
from typing import Any

import pandas as pd

from incident_analyzer.ingestion import (
    ImportLimitError, ImportSession, MAX_FILE_BYTES, MAX_SESSION_BYTES, MAX_INPUT_RECORDS,
)
from incident_analyzer.models import FileImport, InputFile, NormalizedEvent
from incident_analyzer.case_state import ensure_case, uploader_key
from incident_analyzer.evidence_manifest import manifest_json

MAX_SESSION_RECORDS = MAX_INPUT_RECORDS
ERRORS_PER_PAGE = 25
EVENTS_PER_PAGE = 100
OCCURRENCES_PER_PAGE = 25
SYNTHETIC_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"
SYNTHETIC_DATASETS = ("normal_activity", "suspicious_sequence", "edge_cases")
SYNTHETIC_FORMATS = {"CSV": "csv", "JSONL": "jsonl"}
NO_TIMEZONE = "None (reject timestamps without an offset)"


def get_import_session(state) -> ImportSession:
    """Per-user session only. Never cached globally or written to disk."""
    if "imports" not in state:
        state["imports"] = ImportSession()
    return state["imports"]


def timezone_options() -> list[str]:
    return [NO_TIMEZONE] + sorted(zoneinfo.available_timezones())


def selected_timezone(choice: str) -> str | None:
    return None if choice == NO_TIMEZONE else choice


def synthetic_path(dataset: str, fmt: str) -> Path:
    if dataset not in SYNTHETIC_DATASETS or fmt not in SYNTHETIC_FORMATS.values():
        raise ValueError("Unknown synthetic dataset")
    return SYNTHETIC_DIR / f"{dataset}.synthetic.{fmt}"


def run_import(st, files: list[InputFile], tz: str | None) -> None:
    session = get_import_session(st.session_state)
    try:
        results = session.import_files(files, assumed_timezone=tz)
    except ImportLimitError as exc:
        st.session_state["import_message"] = ("error", f"Entire batch rejected, nothing imported: {exc}")
        return
    st.session_state["last_import_ids"] = [r.import_id for r in results]
    failed = sum(1 for r in results if r.file_error)
    accepted = sum(r.accepted for r in results)
    rejected = sum(r.rejected for r in results)
    duplicates = sum(r.duplicates for r in results)
    st.session_state["import_message"] = (
        "warning" if failed or rejected else "success",
        f"Read {len(results) - failed} of {len(results)} file(s); {failed} failed to read. "
        f"Accepted {accepted} occurrence(s), rejected {rejected} record(s), "
        f"duplicates {duplicates}. File readability does not mean all records were accepted.",
    )


def explain_limits(st) -> None:
    st.caption(
        "Limits: 10 MB per file (10,000,000 bytes); 20 MB cumulative per session "
        "(20,000,000 bytes, re-imports of the same file count again); 50,000 cumulative "
        "data records. If any limit would be exceeded, the entire submitted batch is "
        "rejected and nothing from it is kept."
    )


def precheck_uploads(uploads, session: ImportSession) -> str | None:
    for upload in uploads:
        if upload.size > MAX_FILE_BYTES:
            return f"A file is {upload.size:,} bytes, over the 10,000,000 byte per-file limit."
    total = session.total_bytes + sum(u.size for u in uploads)
    if total > MAX_SESSION_BYTES:
        return f"Batch would bring the session to {total:,} bytes, over the 20,000,000 byte limit."
    return None


def render_upload_section(st, tz: str | None) -> None:
    st.subheader("Upload exported files")
    uploads = st.file_uploader(
        "CSV, JSONL or Windows XML files", type=["csv", "jsonl", "xml"], accept_multiple_files=True,
        max_upload_size=10, key=uploader_key(st.session_state),
    )
    if st.button("Import uploaded files", type="primary", disabled=not uploads, key="import_uploads"):
        problem = precheck_uploads(uploads, get_import_session(st.session_state))
        if problem:
            st.session_state["import_message"] = ("error", "Entire batch rejected, nothing read: " + problem)
        else:
            try:
                files = [InputFile(filename=u.name, content=u.getvalue()) for u in uploads]
            except (OSError, ValueError, TypeError):
                st.session_state["import_message"] = (
                    "error", "A selected file could not be read. Nothing in this batch was imported.",
                )
                return
            run_import(st, files, tz)


def render_synthetic_section(st, tz: str | None) -> None:
    st.subheader("Bundled synthetic samples")
    st.caption("Fabricated training data. Only the selected sample file is read.")
    col1, col2 = st.columns(2)
    dataset = col1.selectbox("Sample", SYNTHETIC_DATASETS, key="synthetic_dataset")
    fmt_label = col2.selectbox("Format", list(SYNTHETIC_FORMATS), key="synthetic_format")
    if st.button("Import synthetic sample", key="import_synthetic"):
        path = synthetic_path(dataset, SYNTHETIC_FORMATS[fmt_label])
        try:
            content = path.read_bytes()
        except OSError:
            st.session_state["import_message"] = ("error", "The bundled sample file could not be read.")
            return
        run_import(st, [InputFile(filename=path.name, content=content)], tz)


def render_import_message(st) -> None:
    message = st.session_state.pop("import_message", None)
    if message:
        kind, text = message
        {"error": st.error, "warning": st.warning, "success": st.success}[kind](text)


def render_cumulative_metrics(st, session: ImportSession) -> None:
    failed = sum(1 for f in session.files if f.file_error)
    cols = st.columns(3)
    cols[0].metric("Files imported", len(session.files) - failed)
    cols[1].metric("Files failed", failed)
    cols[2].metric("Distinct events", len(session.events))
    cols = st.columns(3)
    cols[0].metric("Data records", f"{session.total_records:,}")
    cols[1].metric("Imported MB", f"{session.total_bytes / 1_000_000:.2f}")
    cols[2].metric("Validation issues", len(session.errors))
    st.caption(
        f"Cumulative input records: {session.total_records:,} / {MAX_SESSION_RECORDS:,}. "
        f"Cumulative original bytes: {session.total_bytes:,} / {MAX_SESSION_BYTES:,}."
    )
    cols = st.columns(3)
    cols[0].metric("Accepted occurrences", sum(f.accepted for f in session.files))
    cols[1].metric("Rejected records", sum(f.rejected for f in session.files))
    cols[2].metric("Duplicate occurrences", sum(f.duplicates for f in session.files))


def file_row(f: FileImport) -> dict[str, Any]:
    return {
        "Filename": f.filename,
        "Import ID": f.import_id,
        "Imported (UTC)": f.imported_at.isoformat(),
        "Bytes": f.byte_count,
        "Assumed timezone": f.assumed_timezone or "None",
        "Input": f.input_records,
        "Accepted": f.accepted,
        "Rejected": f.rejected,
        "Duplicates": f.duplicates,
        "Distinct added": f.new_events,
        "SHA-256": f.sha256,
        "File error": f.file_error or "",
    }


def render_file_table(st, session: ImportSession) -> None:
    st.subheader("Evidence manifest — full case")
    st.caption(
        "Scope: every file imported into this case, including repeated and failed imports. "
        "Timeline display filters do not affect this manifest or its download."
    )
    st.caption(
        "Input = accepted + rejected. Accepted includes duplicates. Duplicates are accepted "
        "records matching an existing normalized event. Distinct added = accepted - duplicates. "
        "Files that could not be read show a file error and zero input rows."
    )
    st.dataframe(pd.DataFrame([file_row(f) for f in session.files]), hide_index=True, width="stretch")
    st.download_button(
        "Download full-case evidence manifest (JSON)",
        data=manifest_json(session), file_name="shield56_full_case_evidence_manifest.json",
        mime="application/json", key="manifest_download",
        help="Contains full-case file hashes, import metadata, source references, counts, "
        "timezone assumptions and validation locations. Does not contain raw file bytes or analyst notes.",
    )
    for f in session.files:
        with st.expander(f"File details: {f.import_id}"):
            st.text(f"Filename: {f.filename}")
            st.text(f"SHA-256: {f.sha256}")
            st.text(
                f"Input {f.input_records} = accepted {f.accepted} + rejected {f.rejected}; "
                f"duplicates {f.duplicates} of {f.accepted} accepted; distinct added {f.new_events}"
            )
            if f.file_error:
                st.text("File error:")
                st.code(f.file_error, language=None)


def page_slice(st, items: list, per_page: int, key: str, label: str) -> list:
    pages = max(1, -(-len(items) // per_page))
    if key in st.session_state:
        st.session_state[key] = min(max(1, int(st.session_state[key])), pages)
    page = st.number_input(f"{label} page (of {pages})", 1, pages, 1, key=key) if pages > 1 else 1
    start = (int(page) - 1) * per_page
    return items[start:start + per_page]


def render_validation_issues(st, session: ImportSession) -> None:
    st.subheader("Validation issues")
    if not session.errors:
        st.caption("No rejected records.")
        return
    files = sorted({e.filename for e in session.errors})
    choice = st.selectbox("Filter by file", ["All files"] + files, key="issue_file")
    issues = [e for e in session.errors if choice == "All files" or e.filename == choice]
    st.caption(f"{len(issues):,} issue(s)")
    for issue in page_slice(st, issues, ERRORS_PER_PAGE, "issue_page", "Issues"):
        with st.container(border=True):
            st.text(f"{issue.source_ref}  (record {issue.record_position}, lines {issue.line_start}-{issue.line_end})")
            st.text(f"Import {issue.import_id}: {issue.filename}")
            st.text(f"Problem: {issue.message}")
            st.code(issue.source_record, language=None)


def render_reset(st) -> None:
    from incident_analyzer.case_ui import render_case_reset
    render_case_reset(st)


def import_page(st) -> None:
    ensure_case(st.session_state)
    session = get_import_session(st.session_state)
    st.subheader("Import evidence")
    st.write("Import exported Windows security events as CSV, JSONL or Windows XML. Data stays in this session's memory.")
    st.caption("Scope: full case. Accepted counts include duplicate occurrences; analysis uses distinct events.")
    explain_limits(st)
    tz_choice = st.selectbox(
        "Assumed timezone for timestamps without an offset",
        timezone_options(),
        key="assumed_tz",
        help="Applies only to naive timestamps. Ambiguous or nonexistent local times "
        "(DST transitions) are rejected for correction.",
    )
    tz = selected_timezone(tz_choice)
    render_upload_section(st, tz)
    render_synthetic_section(st, tz)
    render_import_message(st)
    session = get_import_session(st.session_state)
    st.divider()
    render_cumulative_metrics(st, session)
    if not session.files:
        st.info("Nothing imported yet. Upload files or import a synthetic sample.")
        return
    render_file_table(st, session)
    render_validation_issues(st, session)


def event_row(event: NormalizedEvent) -> dict[str, Any]:
    row = {"Timestamp (UTC)": event.timestamp_utc.isoformat()}
    row.update({k: v for k, v in event.fields.items() if k != "timestamp"})
    row["Occurrences"] = len(event.occurrences)
    row["Duplicates"] = event.duplicate_count
    row["Event key"] = event.event_key
    return row


def event_id_of(event: NormalizedEvent) -> str:
    value = event.fields.get("event_id")
    return "" if value is None else str(value)


def filter_events(events, query: str, event_ids: list[str]) -> list[NormalizedEvent]:
    needle = query.strip().casefold()
    result = []
    for event in events:
        if event_ids and event_id_of(event) not in event_ids:
            continue
        if needle and not any(needle in str(v).casefold() for v in event.fields.values() if v is not None):
            continue
        result.append(event)
    return result


def render_occurrence(st, occ) -> None:
    with st.container(border=True):
        st.text(f"{occ.source_ref}  occurrence {occ.occurrence_id}")
        st.text(f"Import {occ.import_id}: {occ.filename}")
        st.text(f"File SHA-256: {occ.file_sha256}")
        st.text(f"Record {occ.record_position}, lines {occ.line_start}-{occ.line_end}")
        st.text(
            f"Original timestamp: {occ.original_timestamp} | original offset: "
            f"{occ.original_offset or 'none'} | assumed timezone: {occ.assumed_timezone or 'none'} "
            f"| resolved offset: {occ.resolved_offset}"
        )
        st.text("Original fields:")
        st.dataframe(
            pd.DataFrame([{"Field": str(k), "Value": "null" if v is None else str(v)} for k, v in (occ.original_fields or {}).items()]),
            hide_index=True,
            width="stretch",
        )
        st.text("Raw source record:")
        st.code(occ.source_record, language=None)


def render_event_detail(st, event: NormalizedEvent) -> None:
    st.subheader("Selected event")
    st.text(f"Event key: {event.event_key}")
    st.text(f"Occurrences: {len(event.occurrences)}  Duplicates: {event.duplicate_count}")
    st.caption("Normalized fields (canonical, UTC):")
    st.dataframe(
        pd.DataFrame([{"Field": k, "Value": "null" if v is None else str(v)} for k, v in event.fields.items()]),
        hide_index=True,
        width="stretch",
    )
    st.caption("Source provenance (original data):")
    for occ in page_slice(st, list(event.occurrences), OCCURRENCES_PER_PAGE, "occ_page", "Occurrences"):
        render_occurrence(st, occ)


def timeline_page(st) -> None:
    """Compatibility entry point; full interface lives in its own focused module."""
    from incident_analyzer.timeline_ui import timeline_page as render_timeline
    render_timeline(st)
