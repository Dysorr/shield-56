"""Safe derived exports and opt-in original files, built entirely in case memory."""
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from incident_analyzer.reporting import build_exports
from incident_analyzer.schema import EVENT_FIELDS
from incident_analyzer.timeline_filters import filter_timeline

FULL_CSV = "shield56_full_normalized_timeline.csv"
FILTERED_CSV = "shield56_filtered_normalized_timeline.csv"
FINDINGS_JSON = "shield56_full_case_findings.json"
NOTES_JSON = "shield56_full_case_analyst_notes.json"
MANIFEST_JSON = "shield56_full_case_evidence_manifest.json"
REPORT_MD = "shield56_full_case_report.md"
REPORT_HTML = "shield56_full_case_report.html"


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str).encode("utf-8")


def csv_safe(value):
    if value is None:
        return ""
    text = str(value)
    if text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def timeline_csv(events):
    output = io.StringIO(newline="")
    headers = [*EVENT_FIELDS, "event_key", "source_references", "source_occurrences"]
    writer = csv.DictWriter(output, fieldnames=headers, lineterminator="\r\n")
    writer.writeheader()
    for event in events:
        row = dict(event.fields, event_key=event.event_key,
                   source_references=json.dumps(sorted({o.source_ref for o in event.occurrences})),
                   source_occurrences=len(event.occurrences))
        writer.writerow({key: csv_safe(row[key]) for key in headers})
    return output.getvalue().encode("utf-8-sig")


def current_export_signature(state, include_originals=False):
    """Invalidate prepared output after any case, saved-judgment, or filter change."""
    session = state["imports"]
    relevant = {
        "files": [(f.import_id, f.sha256) for f in session.files],
        "notes": state.get("finding_notes", {}), "conclusion": state.get("case_conclusion", ""),
        "disposition": state.get("case_disposition"),
        "conclusion_saved_at": state.get("case_conclusion_saved_at"),
        "judgments": state.get("report_judgments"),
        "filters": state.get("timeline_display_filters", {}),
        "include_originals": include_originals,
    }
    return sha256(json_bytes(relevant)).hexdigest()


@dataclass(frozen=True)
class ExportBundle:
    files: dict[str, bytes]
    zip_bytes: bytes
    snapshot: dict
    signature: str
    include_originals: bool


def record_download(state, bundle, filename):
    """Record a UI download request; never claim that the client saved the file."""
    data = bundle.zip_bytes if filename == "shield56_investigation_exports.zip" else bundle.files[filename]
    state.setdefault("export_history", []).append({
        "operation": "download_requested",
        "at_utc": datetime.now(timezone.utc).isoformat(),
        "filename": filename, "sha256": sha256(data).hexdigest(), "byte_count": len(data),
        "report_id": bundle.snapshot["report_id"],
        "meaning": "Download control activated; client receipt and disk save are unverified. "
                   "This entry appears in subsequent prepared exports.",
    })


def prepare_exports(state, include_originals=False, generated_at=None):
    """Explicit export preparation, not a claim that a browser saved the bytes."""
    stamp = generated_at or datetime.now(timezone.utc)
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("Export time must include a timezone.")
    session = state["imports"]
    events = session.analysis_events
    filters = dict(state.get("timeline_display_filters", {}))
    filtered = filter_timeline(events, **filters)
    operation = {
        "operation": "export_prepared", "at_utc": stamp.astimezone(timezone.utc).isoformat(),
        "scope": "Full case plus explicitly filtered timeline CSV",
        "include_original_evidence": bool(include_originals),
        "full_timeline_count": len(events), "filtered_timeline_count": len(filtered),
        "filters": filters,
        "meaning": "Prepared in session memory; not proof of a completed browser save or chain of custody.",
    }
    # Do not mutate case history until every output has been successfully generated.
    view = dict(state)
    view["export_history"] = [*state.get("export_history", []), operation]
    metadata = {}
    metadata["timeline_exports"] = {
        "full": {"scope": "FULL CASE distinct normalized events", "count": len(events), "filename": FULL_CSV},
        "filtered": {"scope": "CURRENT FILTERED TIMELINE only", "count": len(filtered),
                     "filename": FILTERED_CSV, "filters": filters},
        "csv_policy": "UTF-8 BOM; null as empty; formula-like strings prefixed with apostrophe. "
                      "Canonical values remain unchanged in the case and report.",
    }
    metadata["original_evidence_in_zip"] = []
    originals = {}
    if include_originals:
        for number, file in enumerate(session.files, 1):
            extension = Path(file.filename).suffix.lower()
            if extension not in (".csv", ".jsonl", ".xml"):
                extension = ".bin"
            safe_name = f"original_evidence/input_{number:05d}{extension}"
            originals[safe_name] = file.original_bytes
            metadata["original_evidence_in_zip"].append({
                "archive_path": safe_name, "import_id": file.import_id,
                "original_filename": file.filename, "sha256": file.sha256,
            })
    view["export_metadata"] = metadata
    exports = build_exports(view, stamp)
    snapshot = exports.snapshot
    manifest = snapshot["manifest"]
    common = {"analysis_time_utc": snapshot["generated_at_utc"],
              "application_version": snapshot["application_version"], "report_id": snapshot["report_id"],
              "input_counts": manifest["counts"], "scope": "FULL CASE"}
    files = {
        FULL_CSV: timeline_csv(events), FILTERED_CSV: timeline_csv(filtered),
        FINDINGS_JSON: json_bytes(dict(common, findings=snapshot["findings"],
                                     configuration=snapshot["configuration"], rule_versions=snapshot["rule_versions"])),
        NOTES_JSON: json_bytes(dict(common, finding_notes=state.get("finding_notes", {}),
                                   conclusion=snapshot["case_conclusion"], judgments=snapshot["analyst_judgments"],
                                   previous_finding_notes=snapshot["previous_finding_notes"])),
        REPORT_MD: exports.markdown.encode("utf-8"), REPORT_HTML: exports.html.encode("utf-8"),
        MANIFEST_JSON: json_bytes(manifest),
    }
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        for filename, data in sorted({**files, **originals}.items()):
            info = ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, data)
    state["export_history"] = view["export_history"]
    return ExportBundle(files, buffer.getvalue(), snapshot,
                        current_export_signature(state, include_originals), include_originals)
