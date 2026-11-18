# Shield 56 — deterministic detection specifications

**Implemented rules R1, R2, R3, version 1.0.0.** Findings are investigative
leads, not conclusions of compromise or malicious persistence. No AI/API,
randomness, current clock, dataset label or evaluation answer determines a match.

## Shared inputs and configuration

`analyze(ImportSession, config=DEFAULT_CONFIG)` consumes only distinct normalized
events through `detection_events`. Duplicate occurrences do not increase counts.
Every supporting source occurrence remains available, including repeated imports.
UTC order is `(timestamp_utc, full normalized event fingerprint)`; file order
cannot change a finding's identity or tie-breaking.

`incident_analyzer/rule_config.py` is the single runtime source of defaults:

| Parameter | Default |
| --- | --- |
| `failure_threshold` | 5 distinct failures |
| `failure_window_minutes` | 5 |
| `success_window_minutes` | 10 |
| `task_window_minutes` | 15 |

The frozen `RuleConfig` can be passed programmatically. Values must be integers
(not booleans), from 1–1440; the failure threshold must be at least 2.
The UI uses defaults and displays the actual configuration and rule versions.
Every `AnalysisResult` records them. Changes to matching semantics require a
rule-version change; configuration changes are also included in finding IDs.

Required timeline and rule-specific fields are listed in
[ingestion.md](ingestion.md#additional-fields-for-the-planned-detections).
Missing correlation keys never match each other or act as wildcards. Unknown IDs
stay visible but do not participate in these three rules. Provider and channel
are retained, not extra rule filters: verify that input IDs represent Windows
Security events rather than assuming another provider uses identical semantics.

## R1 — Repeated failed logons

Eligible records: event **4625**, with non-null host, target domain, target user,
and source IP. These four normalized fields define the group. Account/domain/
hostname comparison is case-insensitive; IP comparison uses canonical addresses.
**Logon type is not an R1 grouping field and is not required for R1.**

At each failed event at time `t`, examine `[t − 5 minutes, t]`, inclusive of
both ends. At least five distinct events qualify. The implementation slides
two indexes through each time-ordered group; it does not compare every pair.

Merge qualifying windows when they share at least one supporting failure,
transitively. An episode retains the union of their failures, exactly once each.
Thus a sustained sequence can span more than five minutes while each original
qualifying window satisfied the threshold. A nonqualifying gap does not itself
join episodes. Report one R1 finding per episode; its first/last timestamps are
the earliest/latest supporting failures. Do not create a finding per window.

Severity **Medium**: concentrated failures need review but can be caused by
password typos, stale service credentials or troubleshooting. Check raw failure
status, account activity, source ownership and endpoint/identity records.

## R2 — Successful logon following repeated failures

Eligible record: **4624** whose host, target domain/user and source IP match
an R1 group, with an explicit logon type.

The success must be **strictly after the final failure of the complete R1
episode**, and no more than ten minutes later. Equal timestamps do not qualify;
the upper bound does. An intermediate success during a continuing failure
episode is not a match to its eventual final failure.

“Compatible” means exact equality with the final failure's non-null logon type.
No equivalence between Windows logon types is invented. Earlier failures in
the episode may have other types. If several failures share the final timestamp,
all their types must be present and equal; mixed or unknown final types prevent
R2. This intentionally conservative policy can miss a genuine sequence.

### Multiple successes and episodes

Assign each success to the nearest preceding **compatible** R1 episode for its
complete group, within the ten-minute bound. A success is never reused across
episodes. Then retain the earliest assigned success per episode; same-time ties
are broken by normalized event fingerprint, not input order.

Emit at most one R2 finding per episode. All other successes remain in the
timeline, but are not alternate R2 anchors or automatically evidence of the
chosen link. R2 support is every R1 failure plus the selected success. Its first
timestamp is the first failure; its last is the selected success. The
`target_logon_id` is not required until R3.

Severity **High**: the success increases review priority, not certainty. Legitimate
password correction or credential maintenance can produce this pattern.
Check identity/MFA records, user confirmation and session/endpoint activity.

## R3 — Task creation following suspicious authentication

Eligible record: **4698** strictly after the selected R2 success and no more than
fifteen minutes later. Require:

- Same normalized hostname.
- Task **subject domain/user** equal to success **target domain/user**.
- Non-null, **nonzero** success `target_logon_id` and task `subject_logon_id`,
  equal after hexadecimal normalization. `0X00001234` and `0x1234` are equivalent;
  null and any spelling of zero never confirm this link.

The success's subject account and the task's target account are not substitutes.
Task name/content are supporting evidence, not conditions for asserting intent.
Task source IP and logon type are not required. The finding's displayed source IP
comes from authentication; the explanation explicitly identifies that scope.

### Host-scoped IDs, reuse and multiple tasks

Windows logon IDs are **host-scoped and can be reused**, for example across
restarts. Inspect all imported 4624 records with that host/session ID, not just
selected R2 successes. The most recent strictly preceding logon must be the
selected R2 success. An intervening reuse, even by the same account, prevents
linking the task to the older R2 anchor. Multiple distinct logons tied at the
latest time, or any logon tied with the task time, make ordering ambiguous:
do not produce R3 from that link.

All qualifying task creations anchored to the same R2 success form **one R3
finding**, retaining every distinct task and all its source occurrences.
This avoids repeating a long failure episode once per task. Additional task
records are still individually visible in the support table. Support is all
R1 failures, the selected success and all qualifying tasks; first/last timestamps
span that complete evidence set. The fifteen-minute bound is measured separately
from the success to each task, not from the first failed event.

Severity **High**: investigate the session-linked task creation; do not declare
malicious persistence. Authorized administrators, installers and maintenance
tools create tasks legitimately. Inspect task definitions without executing
them; verify authorization, logoff/reboot evidence, processes and scheduler logs.

## Finding output and provenance

Each finding contains its stable ID, rule ID/name/version, first/last UTC times,
normalized host/account, source IP with the scope noted above, plain-language
explanation, severity and rationale, benign explanations, analyst checks, and
related findings. Severity expresses investigation priority, not probability.

Supporting event objects pair each normalized event key and Windows record ID
with **that event's** source references and occurrences. Flat reference lists
are also retained. A stable source reference is file SHA-256 plus record
position; a Windows `record_id` alone is neither globally unique nor sufficient
to locate original evidence. Reimporting the same file retains new occurrences
even though its stable references repeat. Raw values and records are available
in the Findings and Timeline views and rendered as text, never executable HTML.

Finding ID = rule prefix plus SHA-256 of deterministic JSON containing the
rule ID/version, active configuration and ordered distinct supporting event keys.
It excludes filenames, file order, import time and occurrence counts. Reordered
input or duplicate imports preserve finding IDs; changed evidence/configuration
may legitimately change them. Provenance always reflects the actual imports.

## Verification and limitations

Tests independently specify IDs, support sets, thresholds, exclusions and
boundary expectations. The separate evaluation-only key specifies the synthetic
sequence: R1 supports 2101–2105; R2 adds 2106; R3 adds 2107. The runtime and
generator never read it. Both CSV and JSONL must produce those same findings.
The earlier provisional evaluation windows were superseded by this requested
five/ten/fifteen-minute contract.

Tests cover four failures, inclusive endpoints and microseconds outside them,
strict start bounds, mismatched/missing keys, account roles, mixed logon types,
equivalent hexadecimal IDs, reused IDs, ties, multiple successes/tasks, out-of-order
events, duplicate imports and routine administrator activity.

Absence of findings does **not** mean an environment is safe. Missing exports,
clock skew, NAT/shared IPs, incomplete domains/types/IDs and unseen session reuse
can cause missed or misleading links. Even a complete R3 correlation does not
prove process ancestry or intent. These rules do not estimate detection accuracy,
establish chain of custody, consult threat intelligence, or replace independent
forensic review. Analyst notes and report exports remain a later milestone.
