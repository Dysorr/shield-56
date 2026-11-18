# Shield 56 — session-only investigation interface

The case consists of imported files, distinct normalized events and every source
occurrence, validation issues, deterministic full-case findings, finding notes
and a case-level conclusion. It lives in **this Streamlit session's server
memory**. No sensitive evidence or notes enter globally shared caches, a database,
or application-managed files.

## Import and manifest

Choose a bundled, explicitly synthetic dataset or upload CSV/JSONL, then click
the corresponding Import button. Attaching files or changing a selector alone
does not import. Select an IANA timezone explicitly for naive timestamps; an
assumption applies to the submitted import, not retroactively to prior files.
Every occurrence records its original offset, applied assumption and resolved
offset. DST ambiguities/gaps remain rejected for correction.

Review the **full-case evidence manifest**, per-file hashes, counts, metadata,
and located validation messages. Input counts are accepted plus rejected;
accepted includes duplicates. Detection and timeline counts refer to distinct
events, not source occurrences. Unknown Windows event IDs remain visible.

The `shield56_full_case_evidence_manifest.json` download is explicitly **full
case**, regardless of timeline or finding display filters. It includes every
import (including repeats and failed files), source references and positions,
timezone assumptions, validation locations and count definitions. It excludes
raw file bytes and analyst notes; it is not an investigation report or a case
backup. It may still contain sensitive filenames, timestamp text and validation
messages, so handle the download as case metadata. Hashes identify bytes, not
authenticity or chain of custody.

## Timeline and chart scope

Timeline filters select UTC start/end **calendar dates**, hostname, account,
event ID, source IP and free-text field search. Both date bounds are inclusive;
an empty bound means unrestricted. Dates are interpreted in UTC, not the user's
browser timezone. A reversed date range shows an error rather than silently
changing the selection.

The account filter uses the logon **target** for 4624/4625 and task **subject**
for 4698. Missing values remain distinct from actual account or IP values.
Within one multi-select, any selected value matches; across different filters,
all conditions must match. The table is ordered chronologically by UTC, with
stable event-key tie breaking, and shows full-case and filtered counts.

The event-volume chart describes the **filtered timeline**, not the full-case
detector input. It counts distinct events in UTC-aligned bins, including zero
bins between observations. Bin width is a whole number of minutes, chosen
automatically to keep the chart at most 240 bins; it is displayed with the chart.
The UTC temporal axis preserves elapsed-time spacing. A zero means no imported,
matching events in that bin, not evidence that a machine was inactive.

**No timeline display filter changes the input to R1/R2/R3.** The findings view
always analyzes all current distinct case events. Rule/severity controls on
Findings only filter which full-case findings are displayed. A screen showing
zero timeline matches can still have three full-case findings.

## Findings and Evidence

Select a finding to inspect its explanation, severity rationale, benign
alternatives, analyst checks and supporting records. Every evidence link refers
to a normalized event and all its original source occurrences. The dedicated
Evidence view also supports inspection outside a finding.

Evidence inspection includes normalized fields, original fields/raw record,
source filename, SHA-256, record position, physical line span and timezone
provenance. Imported text is shown literally in text/code/tables, not executable
HTML. No task definition is executed. Record IDs alone are not globally unique;
use source references and hashes to locate originals.

## Analyst notes and dispositions

Attach a note and disposition to an individual stable finding ID, or save a
case-level conclusion and disposition. The choices are:

- `needs investigation`
- `expected activity`
- `suspicious activity`

Dispositions are **analyst opinions**, separate from automatic rule severity.
They do not alter findings, supporting evidence or thresholds. Each text field
is limited to 20,000 characters. Saving retains text only in the session and
shows a UTC saved timestamp. Use the save action before switching views.
Do not interpret “saved” as a durable disk write.

Duplicate imports keep finding IDs and attached notes stable. New distinct
evidence can change an episode and therefore its finding ID. Previously saved
notes are retained as notes for previous findings, clearly separated from
current results; they must not be silently reassigned to a different finding.

## Reset and session lifetime

**Reset case** is available throughout the app and requires explicit confirmation.
It clears all imported files/bytes, normalized events, validation issues,
derived selections/results, notes, conclusions, filters, timezone selection
and uploader widget state. Uploader identity rotates so stale selected files
do not reappear or automatically reimport. The empty case is ready for a new
investigation. Reset cannot recover unsaved or session-saved work.

Refreshing the browser, ending/reconnecting the session, or restarting the
server can lose **both unsaved edits and session-saved work**. Retain original
exports independently. The manifest is not a backup of notes or evidence.
Production authentication and durable case storage are not implemented.
The Reports view exports full-case Markdown/HTML reports with saved notes and
original evidence; see [report-exports.md](report-exports.md). The manifest remains
metadata-only; the report contains sensitive raw records and analyst text.
