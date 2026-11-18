# Full-case investigation report exports

Open **Reports** after importing CSV, JSONL or Windows XML evidence.
Save finding notes and the case conclusion first; unsaved drafts are deliberately
excluded. Reports always cover the **full case**, not timeline filters or the
currently selected rule/finding.
Set the case title and save observations, hypotheses, alternative explanations
and proposed containment/recovery actions in the Reports editor. Click
**Prepare investigation exports** to create a consistent in-memory snapshot.

## Downloads

- `shield56_full_normalized_timeline.csv`: every distinct normalized case event.
- `shield56_filtered_normalized_timeline.csv`: the **current filtered timeline**
  only. Filters persist across navigation. No filters means the full timeline;
  zero matches produces a header-only file. The manifest records filter values,
  row count and scope. Both CSVs include event keys and all stable source references.
- `shield56_full_case_findings.json`: full-case findings, rule versions,
  configuration, evidence references, analysis time and input counts.
- `shield56_full_case_analyst_notes.json`: saved finding notes/dispositions,
  case conclusion and judgments, including separately identified previous findings.

- `shield56_full_case_report.md`: a portable Markdown report.
- `shield56_full_case_report.html`: self-contained HTML, readable offline and
  printable in grayscale using the browser's Print command.
- `shield56_full_case_evidence_manifest.json`: companion full-case import and
  provenance metadata, using the existing manifest format.
- `shield56_investigation_exports.zip`: all seven derived files above. Original
  input files are excluded unless **Include original evidence** is explicitly
  selected. Then exact original bytes are stored under generated paths such as
  `original_evidence/input_00001.xml`, never user-supplied paths. The manifest
  maps these paths to original filenames, import IDs and hashes. Repeated imports
  remain separate entries. The opt-in resets to off for each new case.

The report title is **Shield 56 — Incident Investigation Report**. Both report
formats contain the same ordered sections: scope and generation time, summary,
import counts/denominators, active rule versions and configuration, file hashes,
saved case conclusion/disposition, each current finding and its saved note,
previous-finding notes, validation errors, limitations, and an evidence appendix.
The appendix includes every distinct event's normalized fields and every original
source occurrence, including raw XML and unknown original fields.
The report also includes editable case title, application version from the project
metadata, UTC analysis time, synthetic-data label, relevant UTC timeline,
recommended containment/recovery actions and evidence needed to resolve uncertainty.
Synthetic labeling is based on exact-byte matches to bundled fixtures, not
untrusted filenames. Mixed cases are labeled as mixed; unmatched data is not
asserted to be genuine. The relevant timeline contains finding-supporting events,
or all events when no findings exist; the appendix always covers the full case.

Input counts, parser/validation warnings and timezone assumptions appear in
every report, including reports with no accepted records.

Finding IDs, normalized event keys and source references link the finding
sections to the appendix and manifest. Repeated imports retain all source
occurrences without multiplying independent rule evidence. Rejected rows and
unreadable files remain visible; no findings is explicitly not a safety verdict.

## Scope, reproducibility and safe text

The reporting function recomputes analysis directly from the current ImportSession
and copies saved analyst state. No UI filter is an input. A report records its
generation time in UTC and a content SHA-256 report ID. Repeated generation with
the same evidence, saved notes and supplied generation time is deterministic.
The UI uses the actual generation time at explicit preparation. Subsequent
download clicks use those same bytes. Saved edits, imports, changed filters or
changing the original-evidence option invalidate the prepared bundle; prepare
again to obtain fresh downloads. Unsaved form drafts do not silently enter exports.

CSV fields with formula-like prefixes (`=`, `+`, `-`, `@`, including after leading
whitespace, or leading tab/CR/LF) are prefixed with an apostrophe. CSV quoting
alone is not a formula defense. UTF-8 BOM improves spreadsheet compatibility.
Null becomes an empty cell; original canonical values remain unchanged in the
case and report. Do not strip the safety prefix before opening untrusted data
in a spreadsheet. Consumers should treat imported CSV as text.

## Analyst actions and handling record

Containment and recovery recommendations are **proposed**, not performed, by
default. They are conditional suggestions for authorized review, not commands
the application runs. The analyst can edit them and record performed status,
but must describe who, when and the supporting evidence. Recorded timestamps
identify when the assertion was saved, not independently verified execution.

The manifest/report handling record includes each import's UTC time, exact-byte
hash and result, plus export preparation records. Download controls append
`download_requested` with filename, byte count and SHA-256. Those requests
appear in the next explicitly prepared bundle: a file cannot record the future
click that downloads its own already-fixed bytes. Neither preparation nor
request is proof of client receipt, disk save, legal custody or identity of the
operator. History is session-only and clears on reset.

Reports are template-based, not AI-generated narratives. Findings remain
hypotheses. Analyst text/dispositions are explicitly separate from rule severity
and cannot change the automatic result. Notes for superseded finding IDs are
listed separately, never silently reassigned to current findings.

HTML escapes all imported and analyst text, has no scripts or external resources,
and uses a restrictive content-security policy. Markdown stores evidence and
analyst text inside dynamically sized literal code fences, preventing embedded
backticks, HTML, links or forged headings from becoming active report structure.
The template does not execute task definitions or embedded XML.

## Privacy and limitations

Exports are generated in the current session's memory, not written to project
files or globally shared caches. They include **sensitive raw evidence and saved
analyst notes**. Protect the files after downloading and review them before sharing.
Reset removes case state and current download controls, but cannot revoke copies
already downloaded. Session-saved work may be lost on refresh or session end.

A report is not a restorable case backup. Retain original exported files
independently; a hash supports integrity checking **from the time of hashing**,
not earlier authenticity, completeness or chain of custody. Derived reports
contain raw record text even when original input files are excluded from the ZIP.
Opting into originals does not create a case restore flow or establish incident
accuracy. Native PDF generation,
Windows printing and OS Save dialogs are not part of automated verification.
You can print the HTML to PDF with your browser if needed.
