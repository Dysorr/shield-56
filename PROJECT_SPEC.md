# Shield 56 — project specification

**Security Incident Timeline Analyzer**  
Suggested repository name: `shield-56`.

## Agreed scope

Build a cybersecurity student portfolio project in Python, Streamlit, pandas,
and pytest. Investigate exported Windows security events with a searchable UTC
timeline, deterministic detections, supporting source records, analyst notes,
and template-based report and evidence-manifest downloads.

Process evidence only in the current user's Streamlit session. No shared evidence
cache, database, disk persistence, or external AI API. Analysis must work without
external AI. No production publishing or authentication work is included now.

**Current authorized work:** scaffold/branding, event schema and reproducible
datasets, and CSV/JSONL ingestion with a shared normalized event/provenance model,
explicit limits, a supporting UTC timeline, and deterministic R1/R2/R3 findings.
The current interface milestone adds scoped filters/chart, Evidence inspection,
analyst notes/dispositions and case conclusion, a full-case evidence manifest
download and complete case reset. Current work also includes full-case
Markdown/HTML report exports and browser verification of XML upload/report downloads.

## Milestones

### Standalone GitHub source preparation

- Added Ubuntu/Windows Python 3.13 GitHub Actions matrix, pinned install/run
  instructions for PowerShell and Linux/macOS, synthetic sample reports, and
  three reviewed synthetic screenshots.
- Added repeatable investigation smoke validation. It confirms the clean normal
  case yields zero findings; suspicious CSV yields R1/R2/R3 once each; record
  2107 provenance resolves; filtered timeline is five events; ZIP members equal
  standalone report bytes.
- Reviewed **289 tracked paths** and **520 reachable Git objects** for listed
  credential-pattern matches; zero matches. No event-log/packet-capture paths
  appeared in history. One author/committer email was present but not printed.
  Built a clean 109-file, Git-free source ZIP for a fresh public history.
- In a newly extracted clean directory, `env -u UV_PROJECT_ENVIRONMENT uv sync
  --locked` resolved 40 packages and installed 39. Then all **230 tests passed
  in 23.35 seconds**, scenario/portfolio checks passed, and the standard
  Streamlit server returned health `ok` and root HTTP 200.
- GitHub Actions has not yet run on hosted runners. The Windows event-export
  script was **reviewed only**, not executed on Windows. No source was pushed;
  license and human release approval remain pending.

### Public portfolio preparation

- Rewrote README for completed capabilities, architecture, exact commands,
  input contract, walkthrough, rules, provenance, limitations, measured timing,
  references and an honest AI/human-review disclosure.
- Added synthetic case study using actual verified results and available saved
  observation; did not invent a missing conclusion or human reviewer.
- Added a three-minute demo, screenshot checklist, two verified CV bullets,
  tracked-file triage and GitHub publication/release instructions.
- Tracked-file review: 283 paths; zero credential-pattern matches; nine
  evidence-format files, all synthetic. History and independent human review
  remain outside this check; publication is not authorized or performed.
- Scenario validator passed all six format/scenario combinations. During
  documentation authoring pytest reported 227 passes and one missing link to
  the not-yet-written publication guide. After adding the guide and review,
  `python -m pytest -q tests/test_branding.py` passed all 11 checks, including
  repository-wide relative documentation links. Script compilation and
  `git diff --check` passed. No runtime/schema/detection changes were made.

### Final specification review and measured validation

- Added `docs/validation.md` with commands, coverage, scenario expected/actual
  results, two-browser-session isolation and inspection of every download.
- Added reproducible 10,000-event synthetic benchmark and cross-format scenario
  validator. Three measured runs: ingestion 0.627–0.657 s; detection 0.154–0.264 s
  on the documented environment only; 1,000 findings per rule each time.
- Corrected misleading import success feedback for rejected rows and added an
  all-rejected-file UI regression test.
- Final suite: **228 passed in 21.75s**; compilation and diff checks passed.
- Browser checks covered fresh cases, notes, scoped exports, ZIP byte equality,
  opt-in exact originals, duplicate stability, timezone handling, unknown IDs,
  literal HTML text, reset and separate contexts. See validation document for
  distinctions between browser checks, automated tests and remaining gaps.

### Complete investigation export bundle

- Added full normalized timeline CSV and explicitly filtered timeline CSV,
  findings JSON, notes JSON, manifest JSON, Markdown/HTML report and ZIP.
- Original input files remain outside ZIP by default; explicit opt-in adds
  exact bytes under generated safe names with manifest mappings.
- Saved analyst case title, observations, hypotheses, alternatives and proposed/
  recorded-performed response actions remain editable and separate from facts.
- Report records application version, synthetic fixture labeling, UTC timeline,
  counts/warnings, timezone assumptions, uncertainty and import/export handling.
- CSV formula-prefix escaping preserves canonical evidence; filters persist for
  exporting but never narrow detection. Prepared downloads invalidate on case edits.
- `python -m pytest -q`: **225 passed in 18.67s**.
- `python -m compileall -q app.py incident_analyzer` and `git diff --check`: passed.
- Tests verify exact ZIP entries and byte-preserved opt-in originals, safe names,
  full/filtered/duplicate counts, formula escaping, report references and content
  hashes, warnings, synthetic labels, recorded actions and handling-history scope.
- Streamlit tests exercise prepare, originals opt-in, stale-bundle invalidation,
  saved judgments, filter retention across navigation and cleared opt-in on reset.
- Restarted the managed workflow; clean startup logs and a rendered Reports
  screenshot confirmed the editor. New ZIP browser download dialogs and desktop
  spreadsheet execution were not tested this milestone; file contents were tested directly.

### Windows XML ingestion

- Added safe namespace-aware XML ingestion, exact-byte file provenance,
  original field trees/raw event XML, and existing size/record limits.
- Added synthetic namespace/version fixtures and a Get-WinEvent/ToXml export script.
- Windows execution of the PowerShell script is unverified; see docs/windows-xml.md.
- `python scripts/generate_xml_fixtures.py` generated labeled fixtures.
- `python -m pytest -q`: **199 passed in 22.33s**, including XML encodings,
  namespace/version handling, missing fields, malformed documents, prohibited
  DTD/entities, duplicates, reproducibility and input limits.
- After the final raw self-closing-event boundary fix,
  `python -m pytest -q tests/test_xml_ingestion.py`: **12 passed in 0.79s**.
  `git diff --check` passed. Restarted workflow and inspected clean startup logs
  and the rendered uploader accepting CSV/JSONL/XML. Actual XML browser upload
  and Windows PowerShell execution remain unverified; parser tests use real bytes.

- [x] **1. Scaffold and startup**
  - [x] Create `app.py`, small `incident_analyzer/` modules, `tests/`, `docs/`,
    `data/synthetic/`, `scripts/`, and README.
  - [x] Use available Python 3.13.11 and record resolved dependency versions.
  - [x] Configure Run to launch Streamlit at `0.0.0.0:$PORT` (assigned 21819).
  - [x] Minimal page explicitly distinguishes scaffold from analysis features.
  - [x] Run relevant tests and record actual results.
  - [x] Confirm startup and inspect the rendered page.
- [x] **2. Ingestion and normalization**: define supported export schema/formats,
  generate labeled synthetic examples, validate records and counts, preserve
  source identity, normalize timestamps to UTC; test valid and invalid inputs.
  - [x] Define and implement the sixteen-field typed record schema and CSV scalar
    decoder with explicit nulls, original timestamps, UTC view and source identity.
  - [x] Generate reproducible, separately loadable normal/suspicious/edge datasets
    in paired CSV and JSONL, with synthetic labels and deterministic hashes.
  - [x] Keep target and subject accounts/logon IDs distinct.
  - [x] Separate evaluation answer key from events and runtime code.
  - [x] Add file ingestion UI, validation summaries, input limits, provenance,
    and explicit deduplication policy.
- [x] **3. Searchable timeline**: session-only evidence, UTC order, search and
  filters, record inspection; test ordering, filters, and session separation.
- [x] **4. Deterministic detections**: specify rules and thresholds, show findings
  with source-record links; test positives, negatives, boundaries, and false positives.
- [x] **5. Analyst conclusions and exports**: notes, conclusions, report templates,
  evidence manifest and downloads; test content and traceability.
  - [x] Session-only finding notes, analyst dispositions and case-level conclusion.
  - [x] Full-case evidence manifest download with explicit scope.
  - [x] Template-based investigation report export.

## Report exports and XML browser verification

- Added full-case Markdown and offline printable HTML reports, plus a companion
  manifest. Includes exact source references, raw evidence, active configuration,
  UTC times, saved notes/dispositions, conclusion, validation issues and limitations.
- Rendering is literal/safely escaped; current timeline/finding filters never
  change report scope. Generation occurs only in session memory, with no AI/API.
- Notes on previous findings remain separate. Drafts are excluded and explained.
- Reports are not restorable case backups and do not revoke downloaded copies.
- `python -m pytest -q`: **207 passed in 16.95s**.
- `python -m compileall -q app.py incident_analyzer` and `git diff --check`: passed.
- Tests cover full-case scope despite filters, current/superseded saved notes,
  raw XML provenance, duplicate occurrences, rejected files, safe literal HTML/
  Markdown, deterministic fixed-time generation and clearing downloads on reset.
- Workflow restarted with clean startup logs; `/reports` rendered its empty state.
- Actual XML-upload-to-report browser journey **passed**: uploaded the 14,202-byte
  synthetic XML through the normal input, accepted 19 events with zero errors or
  duplicates, produced R1/R2/R3, saved an R3 note/disposition and case conclusion,
  and retained 19 events/3 findings in Reports despite the five-event timeline filter.
- Fetched all three actual download responses in the browser: HTTP 200 with
  expected MIME types, filenames, counts, source hash, configuration and evidence.
  Markdown and HTML shared the same report ID and included saved analyst text.
  HTML evidence was escaped, with no script or external-resource elements.
- Confirmed reset removed report controls and emptied the XML uploader/case.
- Unverified: OS/browser download-manager file saving, rendered HTML printing/
  print-to-PDF, and the PowerShell script on Windows. The optional DTD browser
  negative test was not repeated; automated parser tests cover rejection.

## Case interface milestone

- Five working case views: Import, Timeline, Findings, Evidence and Analyst notes.
- Timeline UTC date/host/account/event-ID/IP filters and event-volume chart are
  display-only; detection always uses the full case. Every view/download states scope.
- Literal original/normalized evidence with file hashes, positions and timezone
  provenance; notes are analyst opinions separate from rule severity.
- Complete confirmed reset removes evidence, results, notes, conclusions and
  uploader state. Session-only saves are not durable; refresh/end/restart may lose work.
- No new dependencies, shared caches, persistent evidence storage or AI APIs.
- Verification:
  - `python -m pytest -q` — **186 passed in 18.14s**.
  - `python -m compileall -q app.py incident_analyzer` — passed.
  - `git diff --check` — passed.
  - Focused normal-control AppTest checks cover import, timezone assumptions,
    all timeline filters/counts, invalid date ranges, full-case findings despite
    filters, evidence selection, literal text, saved notes/dispositions, case
    conclusion, previous-finding notes and complete reset.
  - Manifest structure/hash/source mappings, UTC calendar bounds, chart totals/
    bounded bins, note isolation and uploader identity rotation have unit tests.
  - Managed workflow restarted; clean startup logs on `0.0.0.0:21819`.
  - Browser journey verified synthetic import and actual CSV upload, duplicate
    counts, filtered timeline versus full-case findings, source inspection,
    notes/conclusion save and retention across navigation, and full-case reset
    clearing uploads and case data.
  - Browser testing found stale selectbox labels after filtering, a confirmation
    checkbox that stayed checked after reset, and a chart date-parsing warning.
    Fixed option-sensitive widget identity, reset-confirmation identity rotation,
    and numeric UTC epoch data for the chart. A targeted browser recheck passed:
    narrowed finding/event labels now match details, and reset leaves its
    confirmation unchecked and its action disabled.
  - After fixes: `python -m pytest -q tests/test_case_interface_ui.py
    tests/test_findings_ui.py tests/test_ingestion_ui.py` — **18 passed in 17.21s**;
    `git diff --check` passed. This includes a new option-change regression test.
  - The browser fetched the actual manifest download response: HTTP 200,
    application/json, full-case scope, 19 input/accepted/distinct events, one file,
    zero rejected/duplicates, and a SHA-256 matching the shown source provenance.
  - The settled UTC chart rendered with readable UTC time and distinct-event
    axes. Vega still emits a transient initial empty-data extent warning while
    chart data arrives; the settled chart works and no continuing warnings were observed.
  - Manual-check gaps: saving the downloaded file through a browser/OS Save
    dialog was not verified (response contents were verified). Date/host/account/IP
    filters were exercised in AppTest rather than the live browser; the live
    browser exercised event-ID filtering. No full accessibility audit or
    production-deployment testing was performed.

## Architecture and guardrails

The Streamlit UI delegates analysis to the Python package, not the reverse.
Parsing and normalization feed a shared normalized event model. ImportSession
retains original file bytes, metadata, source records, located errors and every
occurrence while indexing distinct canonical events. pandas supports display,
not evidence type inference. The detection module consumes distinct events,
groups rolling-window failure episodes, selects subsequent successes, and
correlates task creators using host-scoped nonzero session IDs. Reporting remains unimplemented.
Session initialization creates fresh containers and preserves existing state on
reruns. Never represent dummy findings or synthetic evidence as real observations.
The input and ingestion policies are defined in `docs/event-schema.md` and
`docs/ingestion.md`; rule policies are defined in `docs/detection_specifications.md`.

## Deterministic detection milestone

- Implemented versioned R1/R2/R3 and the Findings UI, with current analysis
  configuration, severity rationale, benign explanations and analyst checks.
- R1 requires five distinct failures in an inclusive five-minute window,
  grouped by host, target domain/user and IP (not logon type). Qualifying
  windows sharing failure evidence form one episode retaining their union.
- R2 selects the earliest compatible success per episode, strictly after
  its final failure and within ten minutes. Multiple eligible episodes assign
  a success to the nearest compatible one, never reusing it.
- R3 groups qualifying task creations per R2 success, strictly after and within
  fifteen minutes, matching task subject to success target account/domain and
  host-scoped nonzero session IDs. Visible intervening reuse blocks the link.
- Findings include cumulative support and correct per-event source mappings,
  retain every occurrence, and use deterministic content/configuration IDs.
- Updated the evaluation-only key's provisional windows/identifiers to the
  requested R1/R2/R3 contract. Runtime code never consults it; tests independently
  state expected support IDs, boundary results and correlation exclusions.
- No notes, exports, AI, persistence or new dependencies added.
- Verification:
  - `python -m pytest -q` — **167 passed in 11.60s**, including 69 rule tests
    and 5 native Streamlit Findings-page tests using real analysis results.
  - `python -m compileall -q app.py incident_analyzer` — passed.
  - `git diff --check` — passed.
  - Restarted the managed Streamlit workflow successfully; startup logs showed
    no application exceptions. A 1200×950 screenshot verified `/findings`
    navigation and its safe empty state. The capture reported two unspecified
    resource 404s without visible page breakage; those resources were not identified.
  - Loaded findings, filters, source mappings across CSV/JSONL, duplicate reruns,
    reset freshness, no-findings wording and literal HTML evidence were verified
    by AppTest, not by a separate interactive browser session this milestone.
- Unverified: real-incident accuracy, a full-capacity 50,000-event detection
  performance benchmark, published deployment, and analyst/export features
  outside this milestone. Synthetic positives are not evidence of detection accuracy.

## CSV/JSONL ingestion update

- SHA-256 is calculated over exact original bytes before parsing. Store original
  filename, byte count, UTC import time, selected timezone and original bytes.
- Stable source refs combine file hash and record position; separate import/
  occurrence IDs retain repeated imports. Original fields, raw source text,
  timestamps, offsets and applied assumptions are retained per occurrence.
- UTC normalization, casefold account/domain/host keys, normalized IPs and
  hexadecimal logon IDs share one canonical field model. Account roles are
  never swapped; unknown event IDs remain visible.
- Naive times require explicit timezone selection; ambiguous/nonexistent DST
  times are located errors requiring correction.
- Deduplicate on all sixteen canonical event fields, including record ID, not
  timestamp/event ID alone. Detection input contains distinct events while all
  source occurrences remain inspectable.
- Counts: input = accepted + rejected; accepted includes duplicates;
  distinct added = accepted − duplicates. File failures have a separate
  denominator and zero inferred input records.
- Enforce 10,000,000 bytes/file; 20,000,000 cumulative session bytes; 50,000
  cumulative input records. Equality allowed; duplicates/rejections count.
  Over-limit batches make no changes to existing state.
- UI supports explicit sample/upload imports, timezone selection, counts,
  errors, UTC timeline filtering, every provenance reference and confirmed reset.
- Evidence remains session-only; no shared cache, file persistence or AI API.

### Ingestion verification

- `python -m pytest -q`: **93 passed in 10.28s**, covering all earlier tests
  plus normalization/provenance/deduplication/limits and real Streamlit
  sample import, rerun, repeated-format import, safe evidence display and reset.
- `python -m compileall -q app.py incident_analyzer`: passed.
- `curl -fsS http://localhost:80/_stcore/health`: **ok**.
- Workflow restart succeeded; screenshot confirmed the new Import evidence page.
- Browser verification **passed**: sample CSV → matching JSONL → timeline →
  source inspection → confirmed reset. Verified 20 input records, 16 accepted,
  4 rejected, 9 duplicates and 7 distinct events after both edge-case imports.
  Unknown ID 65000 stayed visible, both provenance sources were inspectable,
  and HTML-like evidence was displayed as literal text rather than executed.
- A real 2-row CSV upload was also verified in the browser: no automatic import
  on attachment; clicking Import accepted both events and retained provenance.
  No functional defects were found. Rerun persistence was covered by AppTest;
  navigation/format-change persistence was covered in the browser.
- `python -m pytest -q tests/test_ingestion_ui.py tests/test_branding.py`:
  **16 passed in 5.11s** after replacing deprecated dataframe sizing arguments
  and setting the uploader's displayed 10 MB cap. The core still enforces the
  exact decimal byte limits independently.
- Browser testing noted truncated long quota metric values; changed the metric
  display to short values with a separate wrapping exact-byte/record quota caption.
- After that small display fix:
  `python -m pytest -q tests/test_ingestion_ui.py tests/test_branding.py::test_relative_documentation_links_resolve`
  **6 passed in 6.89s**; `git diff --check` passed. The full 93-test run remains
  the backend/whole-request result; no backend code changed afterward.
- Final workflow restart and fresh startup logs were clean. A 390px screenshot
  confirmed the import controls and displayed 10 MB upload cap fit the screen.
- Documentation identifies the six timeline-required fields and additional
  non-null fields required by each planned detection.
- Unimplemented/unverified: runtime detection findings, analyst notes editing,
  report downloads, Windows execution, real-incident evidence evaluation,
  production publishing, and clean-machine reproduction.

## Event schema and synthetic data update

- Fixed date **2026-01-15**, default local RNG seed **56**, UTF-8, deterministic
  LF serialization. No wall-clock data, UUIDs, network access, or external AI.
- `normal_activity`: **15** rows; `suspicious_sequence`: **19** rows;
  `edge_cases`: **10** rows (8 schema-valid including one duplicate, 7 unique
  valid records, 2 rejected timestamps).
- All sixteen fields are explicit. JSON null maps to an empty CSV cell.
  4624/4625 use target account fields; 4698 uses subject account fields.
- Source timestamps are retained; missing timezones are rejected, never guessed.
  Missing IPs and unknown event IDs remain representable; HTML-like text is inert
  data, not automatically sanitized or rendered.
- The task content describes writing a text marker only; it is never executed.
- Fixture manifest contains synthetic labels, counts, seed, date and hashes only.
- Separate answer key is **evaluation only**. Runtime and generator do not read
  it. Future rules must derive results from events.
- Evaluation windows are specified as: 5 failures in an inclusive 5-minute window,
  matching success within 5 minutes of the last failure, matching actor/session
  task within 10 minutes of success. These are candidate expectations, not an
  implemented runtime detection engine.
- Schema details: `docs/event-schema.md`; reproduction and scenario design:
  `docs/synthetic-datasets.md`.

### Schema/dataset verification

- `python scripts/generate_synthetic.py`: generated **normal_activity 15**,
  **suspicious_sequence 19**, and **edge_cases 10** records in both formats,
  plus the synthetic hash manifest.
- `python -m pytest -q`: **53 passed in 3.79s**. Includes all 17 existing tests
  and new schema/scenario tests: byte-identical repeated generation, independent
  output directories, committed fixture comparison, global RNG isolation,
  alternate-seed background changes, CSV/JSONL/null equivalence, exact sequence
  times/roles/IDs, UTC offset equivalence, deliberate validation errors,
  unknown/HTML-like data preservation, answer-key references and isolation,
  and CLI execution from a different working directory.
- `python -m compileall -q incident_analyzer scripts/generate_synthetic.py scripts/synthetic_scenarios.py`:
  passed.
- Existing UI startup/session/branding tests still passed; a Preview screenshot
  at **1100×800** confirmed the unchanged scaffold renders successfully.
- No packages, Python version, theme, routing, or Run configuration changed.

Not implemented/verified by this update: upload/ingestion UI, dataset selection
in Streamlit, file size limits, deduplication actions, timeline filters, runtime
rule findings, evidence rendering, analyst editing, report downloads, Windows
task execution, or production publishing.

## Reproduction baseline

- CPython: 3.13.11.
- Resolved direct dependencies: Streamlit 1.67.0; pandas 3.1.1; pytest 9.2.0.
- Exact direct pins: `requirements.txt`; transitive lock: `uv.lock`.
- Run: `bash scripts/run_streamlit.sh` via the registered application workflow.
- Tests: `python -m pytest -q`.

## Milestone one verification

- `python --version`: Python 3.13.11.
- `python -m pytest -q`: **5 passed in 2.28s**. Covers empty state,
  preservation across reruns, independent session containers, unrelated state,
  and in-process Streamlit page startup with no upload control.
- `python -m pip check`: unavailable because this environment does not include
  pip. Used the installed uv compatibility checker instead.
- `uv pip check`: **39 packages checked; all installed packages compatible**.
- `uv sync --frozen --check`: **39 packages checked; would make no changes**.
- `curl -fsS http://localhost:80/_stcore/health`: **ok** through preview proxy.
- Managed Streamlit workflow started at `0.0.0.0:21819`. Browser screenshot
  confirmed the minimal page rendered, with the correct title and scaffold notice.
- Initial startup logs showed inotify queue overflow from automatic file
  watching. The launcher disables file watching; code changes need a restart.
- After the launcher change, workflow restart succeeded, fresh logs showed no
  watcher warnings, and the proxied health endpoint again returned **ok**.
- `bash -n scripts/run_streamlit.sh`: passed.
- After project metadata cleanup, the environment check correctly requested a
  refresh of the local package. The package helper attempted unavailable pip;
  `uv sync --frozen` refreshed only the local project package successfully.
  Final `uv sync --frozen --check` made no changes and `uv pip check` again
  reported all 39 installed packages compatible. Dependency versions did not change.

Deferred/unverified: ingestion, timeline, detections, analyst editing, downloads,
Windows export, browser end-to-end testing, production publishing, and
clean-machine installation/reproduction.

## Milestone completion rule

After every milestone: run relevant tests, report actual commands and results,
identify unverified behavior, update this checklist, and explain important code
in student-friendly language. No claims of analysis before it is implemented.

## Branding update

- Exact public name: **Shield 56**; subtitle: **Security Incident Timeline Analyzer**.
- Jordan-inspired palette: main `#0B1220`, surface `#152033`, primary text
  `#F8FAFC`, secondary text `#CBD5E1`, green `#008751`, red `#CE1126`, white `#FFFFFF`.
- Native Streamlit dark theme, sans-serif interface, monospace evidence/code,
  responsive header, accessible Jordanian flag, and narrow flag-color band.
- Use green for primary actions/selected navigation and red only as restrained
  branding. Severity indicators require explicit labels, not brand color alone.
- Future report title: **Shield 56 — Incident Investigation Report**.
- Future downloads use `shield56_`; exports must remain readable in grayscale.
- Imported evidence must be escaped plain text. UTC remains the timestamp standard.
- Stable internal artifact directory, ID, workflow, and package names are retained
  to preserve routing and Run configuration; these are not public product names.
- No new investigation features are added by this branding update.

### Branding verification

- `python -m pytest -q`: **17 passed in 2.78s**, including existing session tests,
  startup, identity/report-name/download-prefix contracts, eight palette contrast
  pairs, static accessible header/theme checks, and README/docs link resolution.
- `python -m compileall -q app.py incident_analyzer`: passed; module imports
  and startup also passed in pytest.
- `uv sync --frozen` refreshed only the local project metadata;
  `uv sync --frozen --check` then reported **39 packages, no changes needed**.
  Python and dependency versions remain unchanged.
- Managed workflow restart succeeded, with clean startup logs and no theme warnings.
- Desktop screenshot at **1280×850** and narrow project-page screenshot at
  **390×844** confirmed the rendered dark theme and readable layout.
- One browser verification pass **passed**: Welcome → Project information →
  Welcome, desktop and 390px. Browser title was exactly **Shield 56**; header
  h1 and flag alt text were present; `/project` and `/` resolved; no horizontal
  overflow was found. The mobile sidebar toggle worked; it remains open after
  navigation until collapsed (native Streamlit behavior).
- Keyboard Tab showed a **2px #7DD3FC focus outline** on the skip link and sidebar
  navigation. Selected navigation matched `aria-current="page"` with a green
  background and visible green indicator.
- Browser-computed contrast: title **15.60:1**, subtitle **11.00:1**, selected
  navigation **12.37:1**, info notice **7.00:1**, warning notice **10.10:1**.
  Automated color-pair checks measured white/green action styling at **4.58:1**,
  green indicator/surface **7.16:1**, and focus/surface **9.79:1**.
  There is no primary action button in this scaffold to inspect interactively.
- Former-name search found only the requested descriptive subtitle in public
  content. Product title and configurable artifact metadata are **Shield 56**.
  Internal directory/workflow identifiers remain stable. No files were renamed;
  relative documentation links were verified by tests.

Imports here means Python module imports: log ingestion, timeline filters,
findings, raw evidence views, notes editing, reset, reports and downloads remain
unimplemented, so their interaction checks are **not applicable**, not passed.
Export names/title are contracts only; no generated report is claimed.
No complete accessibility certification, screen-reader audit, future-component
contrast audit, generated-report print test, or published deployment verification
is claimed. The browser pass did not precisely measure opacity-blended unselected
navigation text.
