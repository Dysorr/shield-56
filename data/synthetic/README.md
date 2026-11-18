# Synthetic evidence only

**Shield 56 — SYNTHETIC ONLY.** Invented Windows-style lab records, not real logs.
Each dataset is separately available as `.synthetic.csv` and `.synthetic.jsonl`:

- `normal_activity`: 15 records, routine successes, two failures, and an admin task.
- `suspicious_sequence`: 19 records, including the prescribed failed-logon,
  successful-logon, and task-creation sequence.
- `edge_cases`: 10 rows with intentional timestamp errors, a duplicate, and
  other documented boundary cases.

Run `python scripts/generate_synthetic.py` from the repository root to reproduce
these files with seed 56 and date 2026-01-15. `manifest.synthetic.json` records
labels, row counts and file hashes; it contains no detection answer key.

See [dataset documentation](../../docs/synthetic-datasets.md) and the
[event schema](../../docs/event-schema.md) for types, account roles, nulls and
invalid-row behavior. The generator never executes task content. No real
security logs should be committed: they can contain sensitive activity.
