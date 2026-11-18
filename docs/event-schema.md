# Shield 56 — event schema, version 1

**Security Incident Timeline Analyzer**

This is the input contract for UTF-8 CSV and JSONL exported-event fixtures.
`incident_analyzer/schema.py` provides the validation factory
`SecurityEvent.from_mapping`, the CSV scalar decoder `decode_csv_record`,
and an explicit UTC timestamp view. `ImportSession` adds file ingestion,
normalization, deduplication and provenance. Native EVTX/XML event-log ingestion
is not supported. See [ingestion.md](ingestion.md) for the full runtime policy.

## Representation and nulls

Generated fixtures have all sixteen columns. The strict `SecurityEvent` factory
expects this complete mapping; the ingestion adapter fills omitted nullable
columns/keys with null and requires only the six timeline fields below.
Extra keys are errors. JSONL has one JSON object per line,
integer numeric fields (not strings, floats, or booleans), and JSON `null`.
Generated CSV has a single header in the documented order; ingestion matches
column names and also accepts other header orders. CSV uses unsigned decimal numeric
cells, and **empty cells for null**. Quoting follows standard CSV rules.
Decode CSV with `csv.DictReader` and `decode_csv_record` before validation.
Do not rely on pandas' inferred types: it can coerce IDs or nulls.

Null means not applicable or not available; those reasons are not distinguishable
in this schema. Never substitute `"unknown"`, `"None"`, `"null"`, zero, an empty
account, or a guessed IP/timezone for a missing value. Present text must be
nonempty. Originals are preserved separately from canonical casefolded comparison
keys; normalization does not overwrite the source values.

| Field | Type | Meaning and null behavior |
| --- | --- | --- |
| `timestamp` | required string | ISO 8601 event time, `YYYY-MM-DDTHH:MM:SS[.ffffff]` with `Z`/`±HH:MM` or an explicitly selected IANA timezone for naive input. Up to six fractional digits. Original text/offset and applied assumption preserved; normalized time is aware UTC. DST gaps/folds require correction. |
| `event_id` | required integer | Windows Security event identifier, 0–65535. 4624 = successful logon; 4625 = failed logon; 4698 = scheduled-task creation. Unknown IDs within range are retained without inventing semantics. |
| `hostname` | required string | Computer that emitted the event. Part of source identity and later correlation; not inferred from the IP. |
| `record_id` | required integer | Positive Windows event record identifier, up to 2^64−1. Unique only in source context; not globally unique. Do not confuse with a logon/session ID. |
| `provider` | required string | Event provider, normally `Microsoft-Windows-Security-Auditing`. Other nonempty provider names are retained. |
| `channel` | required string | Event channel, normally `Security`. Other nonempty values are retained, not assumed Security. |
| `target_user` | nullable string | Account being logged into in 4624/4625. Not the task creator in 4698. Required for target-account detection, not for timeline acceptance. Strict fixture validation requires it for these IDs; ingestion permits null. |
| `target_domain` | nullable string | Domain or machine context of the target account. May be null even when a username exists; do not assume `LAB` or equate missing domains. |
| `subject_user` | nullable string | Actor performing an operation. In 4698, the account creating the task. Required for actor correlation, not timeline acceptance. Strict fixture validation requires it for 4698; ingestion permits null. Never copy a target account just to fill a cell. |
| `subject_domain` | nullable string | Domain or machine context of the subject account. Null if unavailable; distinct from `target_domain`. |
| `source_ip` | nullable string | Valid IPv4/IPv6 source address where reported. Null for an absent/non-applicable source (for example a local task). A `-` placeholder must be explicitly mapped to null by a future export adapter, not accepted as an IP. |
| `logon_type` | nullable integer | Windows logon type (0–65535), e.g. 3 = network. Null if not applicable; unknown numeric types are retained. |
| `target_logon_id` | nullable string | `0x`/`0X`-prefixed hexadecimal logon ID for the target session; e.g. successful 4624 uses `0x1234`. Null if unavailable/not applicable, especially failed logons. Ingestion normalizes case and leading zeros but preserves original text per occurrence. |
| `subject_logon_id` | nullable string | `0x`/`0X`-prefixed hexadecimal ID for the subject's session; e.g. the creating actor in 4698. Same normalization as target IDs; never swap roles. |
| `task_name` | nullable string | Scheduled-task path/name from 4698; optional if the export omits it, null for non-task events. Untrusted plain text, including HTML-like text. |
| `task_content` | nullable string | Original task definition/content where available, null otherwise. May contain XML/quotes/newlines. Treat as inert evidence: never execute, register, or render it as trusted HTML. |

## Account roles and source identity

For 4624/4625, correlate **target_domain + target_user**. For 4698, identify
the creator using **subject_domain + subject_user**. A task may be linked to a
successful logon only when evidence supports it (same host, appropriate time
window, matching actor/target account and non-null session IDs). These are not
interchangeable account columns. No detection engine is added in this step.

The schema helper's `source_identity` is `(hostname, provider, channel, record_id)`.
Ingestion adds stable file-hash/record-position references and separate import
occurrence IDs. Deduplication compares **all sixteen normalized fields**, not
just source identity or timestamp/event ID. Every occurrence is retained.

## Time, malformed records, and safe rendering

Reject malformed dates/times; require an explicit user-selected timezone for
naive timestamps and record that assumption. Differing offsets may denote the
same UTC instant. Original ordering/source text remain on occurrences; the
timeline sorts distinct normalized events in UTC. Null IPs and unknown event
IDs are not schema failures, but cannot justify IP-based correlations.

Raw text is rendered with escaped plain-text components such as
`st.code`, never passed into `unsafe_allow_html=True`. The schema preserves
HTML-like text; it is not an HTML sanitizer. Evidence never enters branded HTML.
The typed model's documented validation entry point is `from_mapping`;
direct dataclass construction is not a substitute for validating untrusted data.

## Synthetic fixtures

See [synthetic datasets](synthetic-datasets.md). Both valid scenarios are complete
schema-valid records. `edge_cases` intentionally includes two invalid timestamps
and an exact duplicate. Without a selected timezone, ingestion reports 8 accepted
occurrences, 2 rejected records, 1 duplicate and 7 distinct events.
