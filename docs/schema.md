# Shield 56 — event schema

**Security Incident Timeline Analyzer**

The implemented input contract is documented in
[event-schema.md](event-schema.md). The schema module validates typed records
and decodes CSV scalars. The application now supports CSV/JSONL uploads, sample
selection, validation summaries, explicit limits, UTC normalization, distinct
events and all original occurrences. See [ingestion.md](ingestion.md) for
provenance, duplicate policy and timeline/detection field requirements.
Native EVTX/XML log-file ingestion remains unsupported.
