# Synthetic case study: failures, success and task creation

**SYNTHETIC ONLY — no real incident or victim.**

## Investigation question and method

Do repeated failures for LAB\alice on LAB-PC01 connect to a subsequent success
and task creation? Imported `suspicious_sequence.synthetic.csv` using the
application's ordinary ingestion and deterministic rules. The same fixture
in JSONL/XML yields the same findings. The runtime does not read the answer key.

Actual verified case: 19 input/accepted/distinct events; zero rejects or
duplicates. Source: 2,634 bytes; SHA-256
`4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780`.
Date: **2026-01-15 UTC**. Thirteen successes, five failures, one task.

## Observed evidence

| UTC | Record IDs | Observation |
| --- | --- | --- |
| 09:00–09:04, one per minute | 2101–2105 | Five 4625 failures for target LAB\alice, LAB-PC01, 192.0.2.10 |
| 09:05 | 2106 | 4624 success for the same target/host/IP, type 3, target logon ID 0x1234 |
| 09:08 | 2107 | 4698 task creation by subject LAB\alice on the same host, subject logon ID 0x1234 |

The task definition writes a harmless text marker. Imported task content is
displayed, never executed. The remaining twelve events are background successes.

Actual findings: **R1 Medium**, support 2101–2105; **R2 High**, support
2101–2106; **R3 High**, support 2101–2107. Each is rule version 1.0.0.
These overlapping evidence sets are not three independently established attacks.
The success target and task subject are different schema roles, deliberately
compared rather than conflated.

## Analyst state actually available

The final verification case was saved as **PRE-CONTINUE-CHECK** with an
observation marker **PRE-CONTINUE-OBS** summarizing R1's repeated failed logons
for alice on LAB-PC01, records 2101–2105. Both appeared in exported JSON,
Markdown and HTML. This is a summary of the verified saved observation, not
a reconstruction of its complete verbatim text.

That particular case had **no saved conclusion**, and the report correctly
said “not saved.” Earlier automated browser exercises saved finding notes
and conclusions, but their complete original text was not retained in the
repository. We do not invent analyst quotations or describe test markers as
independent human judgments. These were agent-operated verification sessions.

## Hypotheses, not observed facts

- **Suspicious interpretation:** repeated guessing followed by successful access
  and task-based persistence. The ordering/session relationship makes this
  worth investigating, but intent and authorization are not established.
- **Benign alternative:** an administrator corrected stale credentials and
  created an authorized maintenance task. The harmless marker payload is
  compatible with a lab demonstration.

Resolve uncertainty using approved change records, account-owner confirmation,
source-host ownership, authentication/MFA context, process telemetry and task
execution history. A task-created event alone does not prove execution.

## Proposed response and reporting

Preserve original exports, confirm identity/source ownership and review the task.
If corroborating evidence warrants it, propose authorized session containment
and credential remediation; verify recovery and audit coverage. **No containment
or recovery was performed by this application or established by this case.**

The full CSV contained 19 events; filtering 4625 produced a five-row CSV without
changing the three findings. JSON, Markdown and HTML included the investigated
case and supporting records. The ZIP contained seven derived files, matching
standalone downloads byte-for-byte. Original files were excluded by default.

Report ID from the final recheck:
`007cc629256ba3b302d0891185278ecedb987968a4fc7dc16627194f16f7d0d8`.
Reproducing the investigation creates a different analysis time/report ID.

## Outcome and limits

The project demonstrated reproducible correlation and evidence-backed reporting,
not detection accuracy on real incidents. Reimports preserved finding counts;
the normal 15-event scenario generated no findings. See
[validation](validation.md) for automated/browser evidence and
[demo script](demo-script.md) to reproduce the presentation.
