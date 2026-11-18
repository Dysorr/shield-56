# Shield 56 validation

## Standalone Windows release verification

On 2026-11-18, the original source ZIP installed successfully with uv on
Windows using CPython 3.13.11. Two tests failed because they depended on
the platform's default text encoding or line endings. The release uses
explicit UTF-8 and preserves the exact bytes of synthetic fixtures across
Git checkouts. The source export includes only the Streamlit theme file
from the configuration directory.

- `uv run --frozen python -m pytest -q --tb=short` passed all 231 tests.
- `uv run --frozen python scripts/validate_scenarios.py` checked both
  scenarios and repeat imports across CSV, JSONL, and XML. Normal activity
  yielded zero findings. The suspicious case yielded one finding per rule.
- `uv run --frozen python scripts/verify_portfolio_case.py` verified the
  evidence reference and seven report and data exports.
- The local Streamlit server started and returned HTTP 200 from its health
  endpoint. The pytest suite exercised the interface state and workflows.
- `uv run --frozen python scripts/benchmark.py` completed three runs with
  10,000 synthetic events and 1,000 findings per rule on each run.
- The PowerShell exporter emitted valid XML with one synthetic event returned
  by a test replacement for Get-WinEvent. An unelevated live Security log
  query was denied by Windows. Live record export remains unverified.

Validation date: **2026-11-15 UTC**. Reviewed against PROJECT_SPEC.md: session-only
ingestion, distinct-event detection, source provenance, scoped timeline filters,
analyst notes and complete derived exports. Historical milestone notes in the
specification are not claims about the current implementation.

## Commands and actual automated results

From the repository root:

```bash
python scripts/benchmark.py
python scripts/validate_scenarios.py
python -m pytest -q
python -m compileall -q app.py incident_analyzer scripts
git diff --check
```

- Benchmark completed all three fresh-session measurements below.
- Scenario validator passed all six scenario/format combinations, including
  a repeated import of each original file.
- Initial pytest: **227 passed in 20.27 seconds**.
- Final pytest after the import-feedback regression fix: **228 passed in 21.75 seconds**.
- Compilation and whitespace/diff checks passed.
- Added executable cross-format scenario validation and a regression guard for
  the benchmark's exact 10,000 unique records and byte reproducibility.
- Browser review found a misleading success banner for readable files whose
  records were rejected. The banner now reports accepted/rejected/duplicate
  counts and uses a warning for rejected rows or failed files.
  `tests/test_import_feedback.py` guards the all-rejected case. Rule semantics
  were not changed.

## Scenario expectations versus actual results

These expectations are independently specified in `scripts/validate_scenarios.py`,
not loaded by runtime detection.

| Scenario | Format | Distinct events | Expected R1/R2/R3 | Actual R1/R2/R3 | After repeat |
| --- | --- | ---: | --- | --- | --- |
| normal_activity | CSV | 15 | 0/0/0 | 0/0/0 | 0/0/0 |
| normal_activity | JSONL | 15 | 0/0/0 | 0/0/0 | 0/0/0 |
| normal_activity | XML | 15 | 0/0/0 | 0/0/0 | 0/0/0 |
| suspicious_sequence | CSV | 19 | 1/1/1 | 1/1/1 | 1/1/1 |
| suspicious_sequence | JSONL | 19 | 1/1/1 | 1/1/1 | 1/1/1 |
| suspicious_sequence | XML | 19 | 1/1/1 | 1/1/1 | 1/1/1 |

The suspicious support sets are 2101–2105 for R1, those plus 2106 for R2, and
those plus 2107 for R3. Reimports add source occurrences, not independent
events. The edge fixture without a timezone assumption has ten input rows:
eight accepted occurrences, two rejected timestamps, one duplicate, seven
distinct events and no findings. Explicit Asia/Amman interpretation accepts
the previously naive row and records the assumption.

## Coverage and evidence

| Requirement | Verification |
| --- | --- |
| UTC offsets, naive timestamps, DST folds/gaps | `test_ingestion.py`, `test_case_interface_models.py`, `test_case_interface_ui.py` |
| Unknown ID 65000, missing optional fields/nulls | Ingestion, synthetic and timeline UI tests |
| Malformed JSONL/CSV/XML, empty inputs, unreadable encodings | Ingestion and XML parser tests; whole-document XML rejection |
| 10 MB/file, 20 MB/session, 50,000 records | Actual byte/record-boundary tests, atomic rollback checks |
| Five-failure threshold, strict starts and inclusive time ends | `test_detection.py`: microsecond inside/on/outside checks |
| Different/missing hosts, users, domains, IPs, logon types and IDs | Detection positive/negative tests, final-type ties, visible ID reuse |
| Duplicate stability and out-of-order input | Detection/ingestion tests plus six-format scenario exercise |
| Supporting references and all occurrences | Detection, reporting and export tests resolve keys/references against manifests |
| Notes, dispositions, proposed/performed actions, reset | Case UI/report/export tests, stale prepared output invalidation |
| Two case objects do not share data | Session and case-state tests; browser evidence recorded separately below |
| Literal HTML-like evidence and report markup | Timeline/findings/notes UI tests, escaped HTML and variable Markdown fences |
| CSV formula prefixes | Export tests cover `=`, `+`, `-`, `@`, leading whitespace/control characters |
| XML safety | Forbidden DTD/internal/external entities, namespaces, alternate encodings and size limits |
| ZIP and original evidence opt-in | Exact seven derived filenames by default; exact-byte originals only on opt-in, safe paths/hashes |

These are real functions and Streamlit widget tests, not mocked detection
answers. Unit boundary checks complement the browser journey; not every
boundary was manually typed into the browser.

## Reproducible 10,000-event benchmark

Run `python scripts/benchmark.py`. It writes ignored generated outputs to:

- `generated-artifacts/validation/benchmark_10000.synthetic.jsonl`
- `generated-artifacts/validation/benchmark-results.json`

Dataset: **SYNTHETIC ONLY**, fixed seed 56 and date 2026-01-15; 1,000 independent
hosts, each with five failures, one success, one task and three background
successes, shuffled reproducibly. No duplicates or invalid input rows.
Expected and observed findings per run: **R1 1,000 / R2 1,000 / R3 1,000**.

- Input records and distinct accepted events: **10,000**
- Bytes: **4,063,894**
- SHA-256: `ae7a139b8edca3431b79f1ed1de4a3527507b76b5180d8323cb20dbfb9f4e6d5`
- Measurement recorded: `2026-11-15T19:59:43.800367+00:00`

| Run | Ingestion seconds | Detection seconds |
| --- | ---: | ---: |
| 1 | 0.656933498 | 0.153968919 |
| 2 | 0.627018750 | 0.263669003 |
| 3 | 0.656133675 | 0.187751169 |

Timing uses `time.perf_counter()` wall time. Each run constructs a fresh
ImportSession, hashes/parses/normalizes/indexes the in-memory JSONL bytes,
then executes `analyze`. Dataset generation and disk I/O are excluded.
No warm-up is discarded. Detection includes sorting and constructing findings
with provenance. UI rendering, downloads, report construction and network
latency are not included. These are three observations, not a latency SLA.

### Environment observed

- Python **3.13.11**
- Streamlit **1.67.0**, pandas **3.1.1**, pytest **9.2.0**
- Linux **6.18.63**, x86_64, glibc **2.40**
- CPU model: **Intel Xeon Platinum 8581C @ 2.30 GHz**
- Visible logical CPUs: **8**
- cgroup CPU quota: `800000 100000`
- Visible memory: `16400676 kB`; cgroup memory limit: `17179869184` bytes

This is a shared Replit development environment. CPU visibility and quota are
not guarantees of dedicated resources. Scheduling, memory pressure and workload
shape can change results materially. No allocation or deployment-tier claim is
made from these observations.

## Manual interface and fresh-session checks

Completed using **two separate Browserbase browser contexts**, with independent
Streamlit websocket sessions, not two views of one session:

- Session A: suspicious CSV, 19 distinct events and three findings.
- Session B: initially empty; normal JSONL, 15 distinct events. A B-only saved
  conclusion did not appear in A. Resetting A left B's data and conclusion intact.
- Repeated CSV in A: 38 accepted occurrences, 19 duplicates, 19 distinct events
  and still three findings.
- XML upload through the normal input in a cleared A: 19 accepted, zero
  rejected/duplicates and R1/R2/R3. XML raw content was checked at file level;
  its in-app raw provenance view was not opened in this final run. XML original
  fields/raw source and traceability are covered by automated tests.
- Edge JSONL after XML: 29 total inputs, 27 accepted occurrences, two rejects,
  one duplicate, 26 distinct events. Unknown ID 65000 remained visible.
  Record 3009's `<script>` task name appeared literally in the raw `<pre><code>`
  display; no alert appeared. Malformed and missing-timezone errors were visible.
- A separate naive-time JSONL input was rejected under None and accepted after
  explicitly selecting Asia/Amman. The UI records the chosen assumption.

### Final fresh case and every download

After clearing A, imported the suspicious CSV, selected 4625 in Timeline (5 of
19), saved an R1 note, conclusion and case judgments, and prepared exports.
All eight download controls were activated and **actual response bytes** were
fetched with that browser session's cookies and saved in the tester's temporary
directory for inspection. This verifies server output, not native OS Save dialogs.

| Output | Bytes | Actual inspection |
| --- | ---: | --- |
| Filtered timeline CSV | 1,597 | UTF-8 BOM, five rows, all 4625 |
| Full timeline CSV | 5,678 | 19 rows: 13 successes, five failures, one task |
| Analyst notes JSON | 2,614 | A's saved note/conclusion present; B-only text absent |
| Evidence manifest JSON | 18,371 | One 2,634-byte CSV source, matching source hash, input count 19; no ZIP originals |
| Findings JSON | 9,286 | Three findings with expected versions/configuration and evidence references |
| Markdown report | 56,336 | Case title, saved judgments/note/conclusion, R1/R2/R3 and counts |
| HTML report | 78,838 | 37 sections, escaped text, no scripts/external resource links; rendered in a browser tab |
| Default ZIP | 25,850 | Exactly seven derived entries; each byte-identical to its standalone response; no original files |

Opting into originals invalidated the old bundle. The new ZIP (28,882 bytes)
included `original_evidence/input_00001.csv`, byte-identical to the 2,634-byte
fixture, with matching SHA-256 and manifest mapping. New preparation legitimately
changed report IDs/timestamps. Reset emptied A's uploader/counters and removed
prepared downloads, while B retained its data. Subsequent narrow XML/literal
checks did not repeat or replace this final fresh-case export inspection.

Remaining interface gaps: native download-manager file saving; in-app XML raw
provenance inspection in this run; desktop CSV execution/printing. The browser
still emits a transient Vega empty-extent warning during chart initialization,
though the settled chart and counts render. Boundary/safety/oversize tests were
automated rather than manually reproducing every case in the browser.

## Pre-continuation recheck (2026-11-15 UTC)

Read this validation record and personally reran the documented command
`python -m pytest -q`: **228 passed in 18.32 seconds**. No failure or supplied
reproduction error was present, so no application code, schema or rules were changed.

After reloading a fresh browser session, imported the suspicious CSV and saved
case title `PRE-CONTINUE-CHECK` and observation marker `PRE-CONTINUE-OBS`.
Confirmed 19 accepted/distinct events, zero rejected/duplicates and three
findings. Timeline filter 4625 selected five records.

All eight download responses returned HTTP 200 and were parsed successfully:
full CSV 19 rows; filtered CSV five rows (2101–2105); findings JSON R1/R2/R3;
manifest source hash matched the fixture; analyst JSON contained the saved
title/observation; Markdown and HTML contained the same case markers, alice,
LAB-PC01 and supporting records 2101–2107. The HTML was rendered in a browser
tab and displayed the case, executive summary and findings. The unsaved
conclusion was correctly labeled not saved.

Report ID: `007cc629256ba3b302d0891185278ecedb987968a4fc7dc16627194f16f7d0d8`.
The ZIP opened successfully: exactly seven derived entries, each byte-identical
to its standalone download, no original files. This recheck did not repeat the
earlier original-evidence opt-in or benchmark. Download bytes were fetched using
the active browser session; native Save dialogs remain unverified.

## Portfolio documentation checks

The portfolio preparation reran `python scripts/validate_scenarios.py`: all six
scenario/format combinations and repeated-import checks passed. The full
pytest run during authoring had 227 passes and one missing documentation link
to the then-unwritten publication guide. After creating that guide,
`python -m pytest -q tests/test_branding.py` passed **11 tests in 0.07 seconds**,
including every relative README/spec/docs link. Unchanged functional tests were
not rerun again merely for prose edits. `python -m py_compile
scripts/review_public_files.py` and `git diff --check` passed.

The tracked-file triage and its limits are in [publication review](publication-review.md).
No application code, schema or detection behavior changed in portfolio preparation.

## Standalone source export and app smoke test (2026-11-18 UTC)

Created `generated-artifacts/publication/shield-56-source.zip`, a 109-file
clean source package with no `.git` directory/history, Replit configuration,
artifact scaffolding, agent-memory files, attachments, caches, private case
paths, or benchmark outputs. It includes the Python application, `.streamlit`
theme, `pyproject.toml`, `uv.lock`, `requirements.txt`, tests, synthetic fixtures,
sample Markdown/HTML reports, synthetic screenshots and Ubuntu/Windows Actions.
The archive was extracted into a new temporary directory outside the workspace.

From that extracted source directory, the actual commands run were:

```bash
python -m pytest -q
python scripts/validate_scenarios.py
python scripts/verify_portfolio_case.py
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 21838 \
  --server.headless true --server.fileWatcherType none --browser.gatherUsageStats false
```

- Clean source tree pytest: **230 passed in 23.58 seconds**.
- Scenario validator: six normal/suspicious × CSV/JSONL/XML combinations passed.
- Portfolio case workflow: normal 15 events/0 findings; suspicious 19 events/
  R1=1, R2=1, R3=1; record 2107 original source and source reference verified;
  selected 4625 filter five rows; full case still 19 events/three findings;
  all seven report bundle files and ZIP byte equality checked.
- Standard Streamlit invocation: `/_stcore/health` returned `ok`, `/` returned
  HTTP 200, server started on the requested local port and stopped cleanly.
- For the isolated install, unset the Replit-only `UV_PROJECT_ENVIRONMENT`
  override in this temporary clean checkout, then ran `uv sync --locked`.
  It created a clean temporary virtual environment, resolved **40 packages**,
  built the local project and installed **39 packages** from the lock.
  This environment was outside the mounted project; the managed app environment
  was not altered.
- In that isolated environment: `uv run --frozen python -m pytest -q`:
  **230 passed in 26.64 seconds** on the final 109-file source package;
  `uv run --frozen python
  scripts/validate_scenarios.py` passed all six combinations; `uv run --frozen
  python scripts/verify_portfolio_case.py` reported 15 normal events/zero
  findings, 19 suspicious events/R1-R3 once each, record 2107 traceability, a
  five-record filter, and successful ZIP/standalone-byte comparison.
- Started with `uv run --frozen python -m streamlit run app.py` in the clean
  checkout: health endpoint `ok`, root HTTP 200, and clean shutdown.
- GitHub Actions has been authored but has **not** run on hosted Ubuntu or
  Windows. This Linux workspace cannot validate Windows execution. The
  PowerShell event-export script was **reviewed only**, not executed on Windows.
- `uv sync` printed a hard-link fallback warning for filesystems spanning
  different devices; it completed package installation successfully by copying.
- GitHub Actions has been authored but has **not** run on hosted Ubuntu or
  Windows. This Linux workspace cannot validate Windows execution. The
  PowerShell event-export script was **reviewed only**, not executed on Windows.

`python scripts/create_public_source_export.py` produced the archive. It is a
source export for review/new Git history; it does not contain `.git` and has
not been pushed to GitHub.

## Remaining limitations

- Windows PowerShell export, actual Security log permissions/audit policy and
  real Windows captures have not been tested on Windows.
- The schema currently supports microsecond timestamp precision (up to six
  fractional digits). Windows exports can contain seven fractional digits;
  those inputs currently require explicit preprocessing and will be rejected,
  not silently rounded. Preserve original exports independently.
- Native browser/OS Save dialogs, printing and desktop spreadsheet formula
  behavior are distinct from verifying served download bytes.
- No production deployment, external security audit, full accessibility audit
  or maximum-capacity/concurrent-load benchmark was performed.
- Session isolation is not authentication, durable storage or forensic custody.
  Refresh/end/reset may lose work. Hashes support integrity from hashing time,
  not earlier authenticity. Handling logs record preparation/requests, not proof
  of client receipt or who controlled the evidence before import.
- A passed synthetic scenario does not establish sensitivity, specificity,
  false-positive rate, precision/recall or detection performance on arbitrary
  incidents. These cases encode known patterns. Real logs may be incomplete,
  differently formatted, clock-skewed, mixed-provider, or affected by session-ID
  reuse, legitimate admin activity and unknown attacker behavior. The benchmark
  likewise cannot predict timings for a dense single-host episode, large task
  payloads, malformed exports, many duplicate occurrences or real incident data.
