"""Full-case, deterministic report snapshots. No disk writes or shared caches."""

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from html import escape
from pathlib import Path

from incident_analyzer.detection import analyze
from incident_analyzer.evidence_manifest import build_manifest
from incident_analyzer.report_context import APPLICATION_VERSION, default_judgments

TITLE = "Shield 56 — Incident Investigation Report"
SCOPE = "FULL CASE: all imported evidence and current findings. Timeline and finding display filters do not apply."
LIMITATIONS = (
    "Findings are hypotheses requiring analyst review, not proof of compromise or malicious persistence.",
    "Severity is investigation priority; analyst dispositions are separate judgments.",
    "Missing events, clock skew and reused host-scoped session IDs may affect correlations.",
    "A hash supports integrity checking from the time of hashing; it does not prove earlier authenticity, completeness or chain of custody.",
    "Only saved notes and conclusions are included; unsaved drafts are excluded.",
    "This report is not a restorable case backup. Preserve original exports separately.",
    "Exports contain sensitive evidence and analyst text; protect downloaded copies.",
)


@dataclass(frozen=True)
class ReportExports:
    snapshot: dict
    markdown: str
    html: str
    manifest_json: str


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def build_snapshot(state, generated_at=None):
    """Analysis always sees the complete ImportSession, never UI filter values."""
    session = state["imports"]
    result = analyze(session)
    stamp = generated_at or datetime.now(timezone.utc)
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("Report generation time must include a timezone.")
    notes = deepcopy(state.get("finding_notes", {}))
    findings = []
    for finding in result.findings:
        row = {
            key: value for key, value in vars(finding).items()
            if key not in ("source_occurrences", "supporting_events", "first_utc", "last_utc")
        }
        row.update(
            first_utc=finding.first_utc.isoformat(),
            last_utc=finding.last_utc.isoformat(),
            analyst_note=notes.pop(finding.finding_id, None),
        )
        findings.append(row)
    fixture_dir = Path(__file__).resolve().parents[1] / "data" / "synthetic"
    fixture_hashes = {sha256(path.read_bytes()).hexdigest()
                      for pattern in ("*.synthetic.csv", "*.synthetic.jsonl", "xml/*.synthetic.xml")
                      for path in fixture_dir.glob(pattern)}
    matched = sum(file.sha256 in fixture_hashes for file in session.files)
    synthetic_label = (
        "SYNTHETIC DATA — all input bytes match bundled training fixtures" if session.files and matched == len(session.files)
        else "MIXED INPUTS — includes verified synthetic training fixtures" if matched
        else "No bundled synthetic fixture identified; data authenticity is not established"
    )
    judgments = deepcopy(state.get("report_judgments", default_judgments()))
    handling = [
        {"operation": "import", "at_utc": file.imported_at.isoformat(),
         "import_id": file.import_id, "filename": file.filename,
         "byte_count": file.byte_count, "sha256": file.sha256,
         "result": "file_error" if file.file_error else "parsed",
         "hash_scope": "Exact original bytes before parsing"}
        for file in session.files
    ] + deepcopy(state.get("export_history", []))
    snapshot = {
        "title": TITLE, "report_version": "1.0", "scope": SCOPE,
        "case_title": judgments["case_title"], "application_version": APPLICATION_VERSION,
        "synthetic_data_label": synthetic_label,
        "analyst_judgments": judgments, "evidence_handling": handling,
        "generated_at_utc": stamp.astimezone(timezone.utc).isoformat(),
        "configuration": result.configuration, "rule_versions": result.rule_versions,
        "exclusions": result.exclusions,
        "manifest": build_manifest(session),
        "summary": {
            "distinct_events": result.distinct_events, "source_occurrences": result.source_occurrences,
            "findings": len(findings),
            "first_event_utc": session.analysis_events[0].timestamp_utc.isoformat() if session.events else None,
            "last_event_utc": session.analysis_events[-1].timestamp_utc.isoformat() if session.events else None,
            "interpretation": "Review the findings and supporting evidence." if findings else
                              "No findings under the active rules. This does not mean the environment is safe.",
        },
        "findings": findings,
        "case_conclusion": {
            "text": state.get("case_conclusion", ""),
            "disposition": state.get("case_disposition", "needs investigation"),
            "saved_at_utc": state.get("case_conclusion_saved_at"),
            "status": "saved" if state.get("case_conclusion_saved_at") else "not saved",
        },
        "previous_finding_notes": notes,
        "evidence": [
            {
                "event_key": event.event_key, "normalized_fields": deepcopy(event.fields),
                "occurrences": [asdict(occ) for occ in event.occurrences],
            } for event in session.analysis_events
        ],
        "validation_errors": [asdict(issue) for issue in session.errors],
        "limitations": LIMITATIONS,
        "evidence_to_resolve_uncertainty": [
            "Complete Security log exports with retention, audit-policy, host-clock and timezone context.",
            "User or administrator authorization and change records.",
            "Identity-provider/MFA records, endpoint process events and task-scheduler logs.",
            "Logoff/reboot records to evaluate reuse of host-scoped logon IDs.",
        ],
    }
    snapshot["manifest"]["evidence_handling"] = handling
    snapshot["manifest"]["integrity_note"] = LIMITATIONS[3]
    snapshot["manifest"].update(deepcopy(state.get("export_metadata", {})))
    snapshot["report_id"] = sha256(_json(snapshot).encode("utf-8")).hexdigest()
    return snapshot


def report_sections(snapshot):
    """A single ordered content contract feeds both human-readable formats."""
    yield "Case identity and analysis time", {key: snapshot[key] for key in
                                   ("case_title", "application_version", "synthetic_data_label",
                                    "scope", "generated_at_utc", "report_version", "report_id")}
    yield "Executive summary", snapshot["summary"]
    yield "Import counts and denominators", {
        **snapshot["manifest"]["counts"],
        "denominators": "Input = accepted + rejected; accepted includes duplicates. "
                        "Distinct events = accepted minus duplicates. Unreadable files have zero input records.",
    }
    yield "Active rules and configuration", {key: snapshot[key] for key in
                                            ("configuration", "rule_versions", "exclusions")}
    yield "Source files and hashes", snapshot["manifest"]["files"]
    yield "Parser warnings and timezone assumptions", {
        "file_errors": [{"import_id": f["import_id"], "warning": f["file_error"]}
                        for f in snapshot["manifest"]["files"] if f["file_error"]],
        "validation_warnings": snapshot["validation_errors"],
        "assumptions": [{"event_key": event["event_key"], "source_ref": occ["source_ref"],
                         "original_timestamp": occ["original_timestamp"],
                         "assumed_timezone": occ["assumed_timezone"], "resolved_offset": occ["resolved_offset"]}
                        for event in snapshot["evidence"] for occ in event["occurrences"]
                        if occ["assumed_timezone"]],
    }
    relevant = {key for finding in snapshot["findings"] for key in finding["supporting_event_keys"]}
    yield "Relevant UTC timeline", {
        "scope": "All finding-supporting distinct events" if relevant else "Full case; no rule findings",
        "events": [{"event_key": event["event_key"], **event["normalized_fields"]}
                   for event in snapshot["evidence"] if not relevant or event["event_key"] in relevant],
    }
    yield "Case conclusion — saved analyst judgment", snapshot["case_conclusion"]
    for number, finding in enumerate(snapshot["findings"], 1):
        yield f"Finding {number} — {finding['rule_id']}", finding
    yield "Previous-finding notes — not current findings", snapshot["previous_finding_notes"]
    yield "Analyst observations, hypotheses and alternative explanations", {
        key: snapshot["analyst_judgments"][key]
        for key in ("observations", "hypotheses", "alternative_explanations", "saved_at_utc")
    }
    yield "Recommended containment and recovery actions", {
        "status_policy": "Proposed only unless the analyst records performed. Performed status is an analyst assertion, "
                         "not independent verification. performed_at_utc is when that assertion was recorded.",
        "actions": snapshot["analyst_judgments"]["actions"],
    }
    yield "Validation errors — rejected source records", snapshot["validation_errors"]
    yield "Limitations and handling", snapshot["limitations"]
    yield "Evidence that would help resolve uncertainty", snapshot["evidence_to_resolve_uncertainty"]
    yield "Evidence-handling record", snapshot["evidence_handling"]
    for number, event in enumerate(snapshot["evidence"], 1):
        yield f"Evidence {number} — normalized event and original sources", event


def render_markdown(snapshot):
    parts = [f"# {TITLE}\n"]
    for heading, content in report_sections(snapshot):
        text = _json(content)
        # Untrusted notes/XML cannot close the literal block, create headings or HTML.
        longest = max((len(match) for match in re.findall(r"`+", text)), default=0)
        fence = "`" * max(3, longest + 1)
        parts.append(f"## {heading}\n\n{fence}json\n{text}\n{fence}\n")
    return "\n".join(parts)


def render_html(snapshot):
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
        f"<title>{TITLE}</title>",
        "<style>body{font:16px/1.5 system-ui,sans-serif;color:#111;background:#fff;"
        "max-width:1000px;margin:32px auto;padding:0 20px}h1{border-bottom:3px solid #111}"
        "h2{font-size:20px;margin-top:32px}pre{white-space:pre-wrap;overflow-wrap:anywhere;"
        "border:1px solid #777;padding:16px;font-size:13px}"
        "@media print{body{margin:0;max-width:none}h2{break-after:avoid}pre{font-size:10px}}</style>",
        f"</head><body><h1>{TITLE}</h1>",
    ]
    for heading, content in report_sections(snapshot):
        parts.append(f"<section><h2>{escape(heading)}</h2><pre>{escape(_json(content))}</pre></section>")
    parts.append("</body></html>")
    return "".join(parts)


def build_exports(state, generated_at=None):
    snapshot = build_snapshot(state, generated_at)
    return ReportExports(snapshot, render_markdown(snapshot), render_html(snapshot),
                         _json(snapshot["manifest"]))
