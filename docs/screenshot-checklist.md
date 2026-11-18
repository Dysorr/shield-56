# Public screenshot checklist

Use only synthetic cases. The three README images are captured examples from the
verified suspicious-sequence case; inspect them against the checks below before
changing them. Do not include personal account menus, workspace URLs, real
source filenames, private notes or credentials. Preserve UTC labels and result
scope. Use readable text, not color-only severity.

- [x] **Timeline:** synthetic 4625 filter, five of 19, UTC axis.
- [x] **Finding and support:** R1/R2/R3, full-case scope, severity and the
  supporting-evidence controls visible. This is a dashboard/context capture;
  it does not show expanded original record details.
- [x] **Report:** generated sample HTML in a rendered browser, with synthetic
  title, 19 events, three findings, hashes and action configuration.
- [ ] Refresh the captures after important UI changes.

Suggested detailed captures for a later update:
  synthetic date 2026-01-15 UTC, LAB-PC01/alice, records
  2101–2107 and total/filtered counts. Suggested caption: “Synthetic authentication
  and task-creation timeline; display filters do not change full-case findings.”
- [ ] **Expanded evidence:** R3 High, rule version/configuration, supporting
  events and original record 2107 with file hash/position. Capture a second image
  if necessary rather than shrinking the text. Caption: “Session-linked task
  creation is an investigative lead, not proof of malicious persistence.”
- [ ] Optional validation image: actual passing test result/date and benchmark
  table with environment/scope, not just an isolated timing number.
- [ ] Check alt text, image readability and repository diff before committing.
  Store approved screenshots in `docs/images/`; do not publish arbitrary
  screenshots from the workspace attachment or browser-test directories.
