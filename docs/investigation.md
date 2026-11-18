# Shield 56 — investigation guide

**Security Incident Timeline Analyzer**

Start the application, open **Import evidence**, and load a labeled synthetic
sample or a supported CSV/JSONL file. Review validation counts/errors and hashes;
then use **Timeline** to inspect UTC events and original source occurrences.
Open **Findings** to inspect R1/R2/R3, the active configuration, and supporting
source records. Consider benign explanations and suggested checks; correlation
does not establish compromise. Use **Evidence** for dedicated source inspection
and **Analyst notes** to save finding notes/dispositions and a case conclusion.
Save is session-only. Full-case manifests and Markdown/HTML reports are downloadable
from Reports. See [case-interface.md](case-interface.md) for scoped filters,
safe notes and reset behavior.
See [ingestion.md](ingestion.md) for timezone/DST decisions, limits and duplicates.

## Evidence workflow

1. Load a labeled synthetic dataset or upload a supported export.
2. Review accepted/rejected counts and record-level validation errors.
3. Search a timeline ordered in UTC.
4. Examine each finding and its original supporting records.
5. Write analyst notes, alternative explanations, and a conclusion.
6. Download the full-case report and evidence manifest; review before sharing.

Preserve original exports separately. Recorded hashes can demonstrate whether bytes
changed; they do not prove authenticity, completeness, or chain of custody.
Use authorized evidence only. This educational app is not a SIEM or a forensic
acquisition tool.
