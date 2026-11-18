"""Full-case report page with explicit, session-only export preparation.

Prepared exports are held only in st.session_state["prepared_exports"] and discarded as
soon as the case, saved notes/judgments, filters, or the originals opt-in change.
Evidence and analyst text are displayed only via st.text, st.code, st.metric and st.json.
"""

from __future__ import annotations

from incident_analyzer.case_state import ensure_case
from incident_analyzer.export_bundle import (
    FILTERED_CSV, FINDINGS_JSON, FULL_CSV, MANIFEST_JSON, NOTES_JSON, REPORT_HTML, REPORT_MD,
    current_export_signature, prepare_exports, record_download,
)
from incident_analyzer.ingestion_ui import get_import_session
from incident_analyzer.judgments_ui import render_judgments

ZIP_FILE = "shield56_investigation_exports.zip"
PREPARED_KEY = "prepared_exports"
INCLUDE_KEY = "include_original_evidence"

FILE_INFO = {
    FULL_CSV: ("Full normalized timeline (CSV) — FULL CASE", "text/csv",
               "All distinct normalized events in the case, regardless of display filters."),
    FILTERED_CSV: ("Filtered normalized timeline (CSV) — FILTERED SUBSET ONLY", "text/csv",
                   "Only events matching the timeline filters stored when exports were prepared."),
    FINDINGS_JSON: ("Findings (JSON) — FULL CASE", "application/json",
                    "All findings with configuration and rule versions. Findings are hypotheses."),
    MANIFEST_JSON: ("Evidence manifest (JSON) — FULL CASE", "application/json",
                    "File hashes, counts, timeline export metadata and evidence handling."),
    NOTES_JSON: ("Analyst notes and judgments (JSON) — FULL CASE", "application/json",
                 "Saved finding notes, conclusion and analyst judgments only."),
    REPORT_MD: ("Report (Markdown) — FULL CASE", "text/markdown",
                "Summary, findings, saved analyst text and evidence with original sources."),
    REPORT_HTML: ("Report (printable HTML) — FULL CASE", "text/html",
                  "Self-contained single file, same content as the Markdown report."),
}


def _render_warnings(st) -> None:
    st.warning(
        "Exports reflect the current case scope and only SAVED notes, conclusion and analyst "
        "judgments; unsaved drafts are excluded. The snapshot is created when you prepare exports."
    )
    st.warning(
        "Downloads contain sensitive evidence and analyst text. This case exists only in this "
        "session; protect any exported copies."
    )


def _render_summary(st, snapshot: dict) -> None:
    summary = snapshot["summary"]
    counts = snapshot["manifest"]["counts"]
    st.subheader("Report summary")
    if snapshot.get("case_title"):
        st.text(f"Case title: {snapshot['case_title']}")
    st.text(f"Scope: {snapshot['scope']}")
    st.text(f"Generated (UTC): {snapshot['generated_at_utc']}")
    if snapshot.get("application_version"):
        st.text(f"Application version: {snapshot['application_version']}")
    if snapshot.get("synthetic_data_label"):
        st.text(f"Data label: {snapshot['synthetic_data_label']}")
    st.text("Report ID (SHA-256 of snapshot):")
    st.code(snapshot["report_id"], language=None)
    cols = st.columns(3)
    cols[0].metric("Files", counts["files"])
    cols[1].metric("Input records", f"{counts['input_records']:,}")
    cols[2].metric("Rejected records", f"{counts['rejected_records']:,}")
    cols = st.columns(3)
    cols[0].metric("Accepted occurrences", f"{counts['accepted_occurrences']:,}")
    cols[1].metric("Distinct events", f"{counts['distinct_events']:,}")
    cols[2].metric("Findings", summary["findings"])
    st.text(f"First event (UTC): {summary['first_event_utc'] or 'none'}")
    st.text(f"Last event (UTC): {summary['last_event_utc'] or 'none'}")
    st.text(f"Interpretation: {summary['interpretation']}")
    st.caption("Findings are hypotheses for analyst review, not conclusions.")


def _render_conclusion(st, snapshot: dict) -> None:
    conclusion = snapshot["case_conclusion"]
    st.subheader("Case conclusion — saved analyst judgment")
    st.caption("Kept separate from findings and original sources in every export.")
    if conclusion["status"] != "saved":
        st.info("No case conclusion saved. Reports will record it as not saved.")
        return
    st.text(f"Disposition: {conclusion['disposition']}")
    st.text(f"Saved (UTC): {conclusion['saved_at_utc']}")
    st.text("Conclusion text:")
    st.code(conclusion["text"] or "(empty)", language=None)


def _render_config(st, snapshot: dict) -> None:
    with st.expander("Active rules and analysis configuration"):
        st.json({key: snapshot.get(key) for key in ("configuration", "rule_versions", "exclusions")},
                expanded=False)
    if snapshot.get("evidence_handling") is not None:
        with st.expander("Evidence handling (included in manifest and report)"):
            st.json(snapshot["evidence_handling"], expanded=False)


def _render_timeline_scope(st, manifest: dict) -> None:
    meta = manifest.get("timeline_exports") or {}
    full, filtered = meta.get("full", {}), meta.get("filtered", {})
    st.subheader("Timeline export scope")
    cols = st.columns(2)
    cols[0].metric("Full timeline events", f"{full.get('count', 0):,}")
    cols[1].metric("Filtered timeline events", f"{filtered.get('count', 0):,}")
    st.text("Filters stored for the filtered CSV:")
    st.json(filtered.get("filters") or {}, expanded=False)
    if meta.get("csv_policy"):
        st.caption(f"CSV policy: {meta['csv_policy']}")
    originals = manifest.get("original_evidence_in_zip") or []
    if originals:
        st.text(f"Original input files in ZIP: {len(originals)} (fixed safe names under original_evidence/)")
    else:
        st.text("Original input files in ZIP: none (not opted in)")


def _render_downloads(st, bundle) -> None:
    st.subheader("Download prepared exports")
    st.caption("The filtered timeline CSV is a subset; every other output covers the FULL CASE.")
    for index, (name, data) in enumerate(sorted(bundle.files.items())):
        label, mime, help_text = FILE_INFO.get(
            name, (f"{name} — FULL CASE", "application/octet-stream", "Prepared export file."))
        st.download_button(
            f"Download {label}", data=data, file_name=name, mime=mime,
            key=f"export_download_{name}", on_click=record_download,
            args=(st.session_state, bundle, name), help=help_text,
        )
    zip_help = "All files above plus manifest."
    if bundle.include_originals:
        zip_help += " Includes original input files (sensitive) under fixed safe names."
    else:
        zip_help += " Original input files are NOT included."
    st.download_button(
        "Download all exports (ZIP)", data=bundle.zip_bytes, file_name=ZIP_FILE,
        mime="application/zip", key="export_download_zip", on_click=record_download,
        args=(st.session_state, bundle, ZIP_FILE), help=zip_help,
    )
    st.caption(
        "Handling log: preparing and each download click are recorded in the case export history "
        "(download clicks as download requested, with a hash of the bytes). A recorded request is "
        "not proof that the browser saved the file. Clicks do not rebuild these exports; the next "
        "explicit preparation includes the updated history. Open the HTML report offline and print to PDF from the browser if needed. "
        "Exports are not a restorable case backup."
    )


def _render_exports(st, session) -> None:
    state = st.session_state
    st.subheader("Investigation exports")
    include = st.checkbox(
        "Include original evidence", value=False, key=f"{INCLUDE_KEY}_{state.get('case_generation', 0)}",
        help="Opt in to add the original imported files to the ZIP.",
    )
    if include:
        st.warning(
            "Original files contain sensitive raw data. They are outside the ZIP by default and "
            "will be added only because you opted in."
        )
    if not session.files:
        st.info("No files imported, so there is nothing to export. You can still edit analyst judgments.")
        state.pop(PREPARED_KEY, None)
        return

    bundle = state.get(PREPARED_KEY)
    if bundle is not None:
        try:
            current = current_export_signature(state, include)
        except (KeyError, TypeError, ValueError):
            current = None
        if current != bundle.signature:
            state.pop(PREPARED_KEY, None)
            bundle = None
            st.warning(
                "Prepared exports were discarded because saved notes, judgments, imports, filters "
                "or the original-evidence option changed. Prepare them again."
            )

    if st.button("Prepare investigation exports", type="primary", key="prepare_exports_button"):
        try:
            bundle = prepare_exports(state, include_originals=include)
        except ValueError as exc:
            st.error("Exports could not be prepared. Check saved judgments and filters, then try again.")
            st.code(str(exc), language=None)
            bundle = None
        else:
            state[PREPARED_KEY] = bundle
            st.success("Exports prepared in session memory from a new snapshot.")

    if bundle is None:
        st.info("No prepared exports. Press Prepare investigation exports to build a snapshot.")
        return
    snapshot = bundle.snapshot
    _render_summary(st, snapshot)
    _render_conclusion(st, snapshot)
    _render_config(st, snapshot)
    _render_timeline_scope(st, snapshot["manifest"])
    _render_downloads(st, bundle)


def reports_page(st) -> None:
    ensure_case(st.session_state)
    session = get_import_session(st.session_state)
    st.subheader("Reports")
    st.write("Record analyst judgments, then explicitly prepare investigation exports from the current case.")
    _render_warnings(st)
    render_judgments(st)
    st.divider()
    if session.files and not session.events:
        st.info("No records were accepted. Exports still document files, hashes and validation errors.")
    _render_exports(st, session)
