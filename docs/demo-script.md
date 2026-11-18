# Three-minute demonstration — SYNTHETIC ONLY

Before recording: use synthetic fixtures in a fresh session, close unrelated
tabs, hide account/workspace identifiers, and prepare the validation document.
Do not display real logs, credentials or the browser's password/account menus.

| Time | Action and narration |
| --- | --- |
| 0:00–0:20 | **Question.** “Can I connect repeated failed logons to a successful session and task creation? This is a synthetic lab case, not a proven compromise.” |
| 0:20–0:40 | **Load.** Import `suspicious_sequence` CSV. Point to 19 accepted/distinct events, zero rejects, file hash. “Evidence stays in this session.” |
| 0:40–1:10 | **Sequence.** Timeline: LAB-PC01/alice, 09:00–09:08 UTC. Show five failures, success, task. Explain target account on logons versus subject account on task creation. |
| 1:10–1:45 | **Evidence.** Findings: R3, supporting 2101–2107. Use the evidence selector to open record 2107. Show original source record, filename/hash/position and subject ID 0x1234; compare success target ID. Do not rely on clicking a table row to select evidence. |
| 1:45–2:05 | **Alternative.** “An authorized administrator could correct a password and create a maintenance task. This marker task is harmless. I'd check change records and endpoint execution before deciding.” Save this as a demo hypothesis, not an established conclusion. |
| 2:05–2:40 | **Report.** Reports: save title “Synthetic portfolio demonstration,” observations and alternatives. Leave actions proposed. Prepare/download HTML or Markdown and ZIP with originals off. Show counts, rules and provenance; explain filtered CSV scope. |
| 2:40–3:00 | **Validation.** Show `docs/validation.md`: 228 passing tests and measured 10,000-event timings. “These checks establish these scenarios, not accuracy on arbitrary incidents. No real-world response outcome is claimed.” |

Run tests before recording rather than waiting for them during the three minutes:
`python -m pytest -q`. Use actual results if the count changes.
Pre-open a synthetic report if download timing would interrupt the demo; label
it as a prepared example rather than pretending it was generated live.

See [screenshot checklist](screenshot-checklist.md). End without resetting unless
you have downloaded what you need; refresh/reset can lose saved session work.
