# Shield 56 — ingestion, normalization, and provenance

## Use the application

1. Open **Import evidence**. Upload one or more `.csv`/`.jsonl` files, or select
   a bundled synthetic dataset and format.
2. Leave the assumed-timezone choice at **None** unless you explicitly know the
   timezone of timestamps without an offset. Choosing a zone does not override
   an offset already present in a record.
3. Click the corresponding **Import** button. Changing widgets or navigating
   does not import anything automatically.
4. Review file hashes, byte sizes, import times, accepted/rejected counts,
   duplicates, and source-located validation errors.
5. Open **Timeline**. Search normalized fields, filter event IDs (including
   unknown IDs), select an event, and examine every original source occurrence.
6. Correct rejected source records outside the app and import the corrected
   file. The original import remains in history. Reset is optional, destructive,
   requires confirmation, and clears ingestion evidence/history only.

All imported bytes, metadata, records and errors live in the current Streamlit
session's server memory. There is no shared evidence cache, disk persistence,
or external API. A reconnect, restart, or confirmed reset may lose the session.
Keep original evidence independently: this is not a forensic acquisition vault.

## Required fields: timeline versus detection

For timeline acceptance, six fields are required and non-null:
**timestamp, event_id, hostname, record_id, provider, channel**.
The ten other defined fields may be absent or null. Ingestion fills omitted
optional fields with null; CSV empty cells and JSON null remain null.
Unsupported extra columns/keys are rejected rather than silently discarded.
An absent account does **not** hide an otherwise valid event from the timeline.
The typed schema helper still supports its stricter fixture-validation mode;
ingestion explicitly disables event-specific account requirements.

Types/ranges and descriptions are in [event-schema.md](event-schema.md).
CSV/JSONL require UTF-8 (optional UTF-8 BOM). XML supports declared encodings
described in [windows-xml.md](windows-xml.md). No delimiter, IP,
account, timezone, or date format is guessed.

### Additional fields for the planned detections

Implemented rules are specified in [detection_specifications.md](detection_specifications.md):

| Candidate | Event types | Additional non-null fields needed |
| --- | --- | --- |
| R1 failed-logon episode | 4625 | `target_domain`, `target_user`, `source_ip`. Host and UTC timestamp come from the timeline-required fields. Logon type is NOT an R1 grouping requirement. |
| R2 success after episode | 4625 + 4624 | Same complete host/target-account/IP key; success logon type must equal the final failure's non-null type (tied final failures must agree). A target logon ID is not required merely to match the success. |
| R3 task after that success | preceding episode/success + 4698 | Success: `target_domain`, `target_user`, nonzero `target_logon_id`; task: `subject_domain`, `subject_user`, nonzero `subject_logon_id`; same host and matching session ID without visible intervening reuse. A task source IP or task logon type is not required. |

Task name/content are evidence to inspect, not required to infer a task's
creating account. Missing domains or IPs must **not** be treated as wildcard
matches or pooled into a single missing-value group. Unknown event IDs stay in
the timeline but are not assigned semantics for these rules.

Account roles are never interchanged: 4624/4625 use the target account; 4698 uses
the subject account. Runtime rule inputs must use `detection_events(session)`,
which returns distinct normalized events, not the source-occurrence stream.
Runtime code never reads the evaluation answer key.

## Exact bytes and source references

Before decoding or parsing a file, calculate SHA-256 over its **exact original
bytes**, including BOM, line endings, spacing, and quoting. `FileImport` retains:

- Original filename, byte count, SHA-256, timezone-selection setting.
- UTC import time and a session-local import ID (`import_1`, etc.).
- The original bytes, file-level errors, and record counts.

Each accepted occurrence retains its original parsed fields, raw source-record
text, original timestamp text/offset, applied assumption, resolved offset, and
physical source lines. CSV originals have string cells/empty cells; JSONL
originals retain JSON types/nulls. They are separate from canonical fields.

Stable reference format: **`<file-sha256>:record:<position>`**.
For JSONL, position is the 1-based physical line number, so blank lines can leave
gaps. For CSV, position is the 1-based logical data-record number excluding the
header/blank rows; separate line-start/end fields cover multiline quoted records.
Renaming or reimporting unchanged bytes preserves the source reference. A separate
occurrence ID (`import_N:record:P`) distinguishes repeated imports of that source.
References therefore do not depend on import time, file name, or row sorting.

A BOM is an encoding marker, not record text; original file bytes retain it.
Error records retain the raw source text even when their fields cannot be parsed.
Unknown encoding/binary data is retained only as original file bytes plus a
file error; it is never guessed into apparently valid records.

## Normalization without altering originals

- Aware ISO 8601 timestamps are converted to an aware UTC datetime and canonical
  ISO string with six fractional digits and `Z`.
- Original text and offset (`Z`, `+03:00`, etc.) remain on each occurrence.
- For naive timestamps, use only an explicitly chosen IANA zone, such as
  `Asia/Amman`. Record that zone on the occurrence; resolved offsets use numeric
  `±HHMM` formatting. Aware timestamps have no applied assumption.
- Round-trip both DST folds through UTC. Zero valid instants means a nonexistent
  spring-forward local time; two means an ambiguous fall-back time. Reject and
  identify either condition; require correction or an explicit source offset.
- Invalid IP addresses are rejected. Valid IPv6 forms are compressed/lowercase;
  IPv4-mapped IPv6 addresses normalize to their IPv4 address.
- Account/domain and hostname comparison fields use Unicode `casefold()`;
  original spelling remains in each occurrence. Roles stay separate.
- Logon IDs require hexadecimal text (`0x` or `0X` prefix) and normalize to
  lowercase, minimal-width `0x` form. Null is not the same as `0x0`.
- Provider, channel, record ID, task names/content and other fields remain part
  of canonical identity. Task content is never executed or trusted as HTML.

## Distinct events and duplicates

The normalized-event key is SHA-256 of a deterministic JSON representation of
**all sixteen canonical event fields**. It excludes file/import metadata,
original timestamp spelling/offset, and timezone-assumption metadata, which are
preserved separately. Matching normalized records within a file, across CSV and
JSONL, and across repeated imports share one event but retain every occurrence.

Record ID is included: timestamp plus event ID is **not** enough to merge.
Different record IDs, account fields, task text, or any other canonical values
remain distinct. Conversely, identical canonical content from two sources is
one analysis event with two provenance references. This content-based policy is
explicit, not a claim that identical content proves historical identity.

## Counts and error recovery

For each file and cumulative imported session:

- **Input records = accepted occurrences + rejected records**.
- **Accepted includes duplicates**, not just new events.
- **Duplicates** are accepted occurrences that match an already indexed
  normalized event, including earlier occurrences in the same submitted batch.
- **Distinct added = accepted − duplicates**. The session's distinct-event count
  is the sum of distinct added, not the number of source occurrences.
- Duplicate proportion, where useful, uses accepted occurrences as denominator;
  rejection proportion uses input records. No percentages are defined for zero.
- CSV header and blank lines are excluded. Every nonblank JSONL line is one
  input candidate, including malformed JSON and non-object JSON values.
- A readable empty/header-only file has zero input/accepted/rejected records.
- An unreadable file or invalid CSV header has a **file error**, zero input
  records, and counts toward failed files, not a fabricated rejected row.
  Other readable files in the batch can still be imported.
- Malformed JSONL rows are rejected individually and processing continues.
  Duplicate JSON keys and non-standard NaN/Infinity values are rejected.
- CSV shape errors and parser errors include logical position/physical lines.
  An unterminated quote can consume the remainder of the file: that unrecoverable
  logical candidate is **one rejection spanning those lines**. No rows are
  invented from text whose record boundaries cannot be determined.

## Enforced limits

- **10 MB per original file = 10,000,000 bytes**.
- **20 MB cumulative original bytes per imported session = 20,000,000 bytes**.
- **50,000 cumulative input records**, including accepted duplicates and rejections.

Exactly equal to a limit is allowed. Repeated imports and failed files consume
their original byte counts; empty files consume zero bytes. Headers/blank lines
consume file bytes but not record quota. Record-unreadable files have zero input
records as above. The file uploader prechecks reported byte sizes before reading;
the import core rechecks actual bytes and counts in all entry paths.
Streamlit may buffer a selected upload before application-level validation; these
are import limits, not a claim about network-transfer limits.

If any size/record limit would be exceeded, **reject the entire new batch**
without altering earlier files, events, references, errors, or counters. Parsing
stages at most the remaining record budget plus the first over-limit candidate.
Clearing browser widgets does not reset quotas; confirmed **Reset case** starts
a new empty case, including clearing notes, conclusions, filters and uploads.
See [case-interface.md](case-interface.md) for full-case and filtered-view scope.
