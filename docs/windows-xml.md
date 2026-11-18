# Windows event XML import and export

CSV, JSONL and Windows event XML are supported. Upload `.xml` on Import evidence.
XML accepts a single Event or an Events wrapper with multiple Event children.
Windows default/prefixed namespaces are recognized; namespace-free wrappers
and events are also accepted. Other namespaces fail explicitly.

System maps TimeCreated/@SystemTime, EventID, EventRecordID, Computer,
Provider/@Name and Channel. Named EventData maps TargetUserName/TargetDomainName,
SubjectUserName/SubjectDomainName, IpAddress, LogonType, TargetLogonId,
SubjectLogonId, TaskName and TaskContent. Target/subject roles are never exchanged.
Missing, empty and `-` values become null; required timeline fields still cause
record rejection when absent. Unknown fields and Version remain in the original
field tree and raw event XML but do not influence normalization.

Exact original file bytes are hashed before parsing and retained in session.
Each occurrence retains the original XML event substring, original element/
attribute tree (including unknown fields), record ordinal and physical line span.
Entity-escaped content remains escaped in raw XML; mapped task text is decoded
as text only, never executed. UTF-8, UTF-16 (BOM or detectable byte order),
ISO-8859-1, Windows-1252 and ASCII declarations are supported.

Python's bundled Expat parser has explicit handlers that reject every DOCTYPE,
entity declaration and external-entity request. Parameter-entity parsing is
disabled. There is no network/file resolver or DTD processing. Nesting is bounded
at 64 levels. Malformed/forbidden XML rejects the entire document before any
events are yielded. Field-invalid records in a well-formed document are rejected
individually with source locations. Existing 10 MB/file, 20 MB/session and
50,000 cumulative-record limits also apply to XML. Empty Events is valid with
zero records; an empty byte file is not an XML document.

## Export existing Windows events

Run in Windows PowerShell with authorization to read the Security log:

```powershell
.\scripts\export_windows_events.ps1 `
  -StartTime '2026-01-15T09:00:00Z' `
  -EndTime '2026-01-15T10:00:00Z' `
  -OutputPath '.\security-events.xml'
```

For an existing saved EVTX file, add `-EvtxPath '.\Security.evtx'`.
The script uses Get-WinEvent with IDs 4624, 4625 and 4698 and the requested time
interval, sorts by time/record ID, and writes each event's ToXml() inside Events.
It refuses an existing output path. Zero matches produces a warning and a valid
empty Events document. Permission/read errors stop with an explanatory error.
If writing fails, a partial output may remain: delete it before retrying.
Use explicit offsets in both times and split large intervals to meet import limits.
Do not upload binary EVTX directly; convert it using this script.

Reading Security generally requires elevated privileges or explicitly delegated
log-read access; group membership alone may not suffice under local/domain policy.
Check policy with your administrator rather than weakening log ACLs. Generating
4624/4625 requires Audit Logon success/failure auditing. 4698 requires successful
Audit Other Object Access Events auditing. Policies must have been enabled when
activity occurred, and records must still be retained. Export cannot reconstruct
missing or overwritten events. This script does not change audit policy.

**Windows execution status: NOT TESTED on Windows.** The Linux workspace does
not provide a Windows Security log. The script requires an authorized Windows
check for permissions, zero matches, time boundaries and EVTX reading.
Python parser tests use synthetic XML only. A real browser upload of the synthetic
XML was also verified end-to-end: 19 accepted events, three findings and full-case
report/manifest download responses with the matching original-file hash. This
does not validate PowerShell execution or actual Windows log access.

Recreate labeled fixtures with `python scripts/generate_xml_fixtures.py`.
They are under `data/synthetic/xml/`, include Windows namespace and versions
0/1/2, and can be uploaded independently. They are not real forensic evidence.
