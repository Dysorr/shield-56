# Shield 56 — reproducible synthetic datasets

**SYNTHETIC ONLY.** These are invented Windows-style lab events, not evidence of
a real incident or actual Windows export captures. Accounts, machines, and
actions are fictitious. Source IPs use the documentation range `192.0.2.0/24`.

## Reproduce

From the repository root:

```bash
python scripts/generate_synthetic.py
python scripts/generate_synthetic.py --output-dir /tmp/shield56-fixtures --seed 56
python -m pytest -q
```

Use the recorded Python 3.13.11 environment. The generator uses a local
`random.Random(56)` instance, fixed date **2026-01-15**, fixed field ordering,
UTF-8, LF line endings, and deterministic JSON formatting. It records no current
time, machine paths, or random UUIDs. Default runs reproduce the committed bytes.
Changing `--seed` changes normal background activity, not prescribed special events.
Byte reproducibility is tested for the recorded Python version, not promised for
arbitrary future Python RNG or serialization implementations.

The output directory contains:

| Dataset | CSV | JSONL | Rows | Purpose |
| --- | --- | --- | --- | --- |
| `normal_activity` | `normal_activity.synthetic.csv` | `normal_activity.synthetic.jsonl` | 15 | Twelve routine successes, two failures below five, one administrator task. |
| `suspicious_sequence` | `suspicious_sequence.synthetic.csv` | `suspicious_sequence.synthetic.jsonl` | 19 | Twelve background successes plus the prescribed seven-event sequence. |
| `edge_cases` | `edge_cases.synthetic.csv` | `edge_cases.synthetic.jsonl` | 10 | Eight schema-valid rows (seven unique), two invalid timestamps. |

All paths above are relative to `data/synthetic/`. Each file can be read
independently; CSV and JSONL encode the **same records in the same order**, including
all deliberate edge-case defects. Each filename identifies it as synthetic;
`manifest.synthetic.json` also labels every dataset synthetic, records the seed,
fixed date and row counts, and hashes each file with SHA-256.
The manifest is fixture metadata, not a forensic evidence manifest or answer key.
The generator rewrites those seven known generated files in the output directory;
keep private evidence elsewhere. It does not delete unrelated files.

## Individually load a fixture in Python

```python
import json
from pathlib import Path
from incident_analyzer.schema import SecurityEvent

path = Path("data/synthetic/normal_activity.synthetic.jsonl")
events = [SecurityEvent.from_mapping(json.loads(line))
          for line in path.read_text(encoding="utf-8").splitlines()]
```

For CSV use `csv.DictReader`, `decode_csv_record`, then `from_mapping`.
The current Streamlit **Import evidence** page can select these samples or upload
CSV/JSONL. The **Timeline** page shows normalized distinct events with provenance.
Deliberate invalid edge-case rows produce located validation errors. **Findings**
derives R1/R2/R3 from the imported events. Without a timezone assumption, the malformed and
naive timestamps are rejected; explicitly selecting a timezone can accept the
naive row and records the assumption.

## Scenario design

The suspicious sequence concerns target `LAB\alice` on `LAB-PC01`, from
`192.0.2.10`, network logon type 3: failures at 09:00–09:04 UTC; success at
09:05 UTC with target logon ID `0x1234`; task creation at 09:08 UTC by subject
`LAB\alice` with subject logon ID `0x1234`. The task definition only describes
writing `SHIELD56_SYNTHETIC_MARKER` to a text file in `%TEMP%`. **The generator
never executes or registers the task.** A task alone is not inherently malicious.

Edge cases include records presented out of order, a byte-equivalent record
duplicate, malformed and timezone-less timestamps, a null IP, `+03:00` and
`-05:00` timestamps representing the same UTC instant, an unknown ID (65000),
and HTML-like task-name text. None of that text is executed or rendered by this step.

## Evaluation-only answer key

`evaluation/scenario_answer_key.json` lists independently specified rule findings and
supporting record IDs, plus expected edge-case validation outcomes. Only tests
and evaluation may read it. It is separate from the fixture directory and manifest;
neither generator nor runtime imports/reads it. Tests enforce that boundary.
Do not expose this key through a future dataset loader or use it to produce findings.

The key specifies the implemented contract: five failures in an inclusive five-minute
window, a compatible success strictly after and within ten minutes of the final
failure, and matching actor/nonzero-session task creation strictly after and within
fifteen minutes of the selected success. It expects
three cumulative findings in `suspicious_sequence` and none in the other scenarios.
Missing correlation fields must not be guessed. These explicit contracts make
expected findings reproducible. Runtime rules derive findings from event fields and are evaluated
against this key rather than loading its answers.
