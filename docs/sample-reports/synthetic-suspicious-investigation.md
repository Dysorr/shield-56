# Shield 56 — Incident Investigation Report

## Case identity and analysis time

```json
{
  "application_version": "0.1.0",
  "case_title": "Synthetic suspicious-sequence training case",
  "generated_at_utc": "2026-11-18T08:12:45.324491+00:00",
  "report_id": "8d2a794606fdfdd5f257c5645b2b6b6b00fc8b2855de11373f0ebfc9226db8e4",
  "report_version": "1.0",
  "scope": "FULL CASE: all imported evidence and current findings. Timeline and finding display filters do not apply.",
  "synthetic_data_label": "SYNTHETIC DATA — all input bytes match bundled training fixtures"
}
```

## Executive summary

```json
{
  "distinct_events": 19,
  "findings": 3,
  "first_event_utc": "2026-01-15T07:01:00+00:00",
  "interpretation": "Review the findings and supporting evidence.",
  "last_event_utc": "2026-01-15T09:08:00+00:00",
  "source_occurrences": 19
}
```

## Import counts and denominators

```json
{
  "accepted_occurrences": 19,
  "denominators": "Input = accepted + rejected; accepted includes duplicates. Distinct events = accepted minus duplicates. Unreadable files have zero input records.",
  "distinct_events": 19,
  "duplicate_occurrences": 0,
  "files": 1,
  "input_records": 19,
  "rejected_records": 0
}
```

## Active rules and configuration

```json
{
  "configuration": {
    "failure_threshold": 5,
    "failure_window_minutes": 5,
    "success_window_minutes": 10,
    "task_window_minutes": 15
  },
  "exclusions": {
    "R1 failures missing grouping fields": 0,
    "R2 successes missing grouping fields or logon type": 0,
    "R3 tasks missing account/domain or nonzero session ID": 0
  },
  "rule_versions": {
    "R1": "1.0.0",
    "R2": "1.0.0",
    "R3": "1.0.0"
  }
}
```

## Source files and hashes

```json
[
  {
    "accepted": 19,
    "assumed_timezone": null,
    "byte_count": 2634,
    "duplicates": 0,
    "file_error": null,
    "filename": "suspicious_sequence.synthetic.csv",
    "import_id": "import_1",
    "imported_at": "2026-11-18T08:12:45.322346+00:00",
    "input_records": 19,
    "new_events": 19,
    "rejected": 0,
    "sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780"
  }
]
```

## Parser warnings and timezone assumptions

```json
{
  "assumptions": [],
  "file_errors": [],
  "validation_warnings": []
}
```

## Relevant UTC timeline

```json
{
  "events": [
    {
      "channel": "Security",
      "event_id": 4625,
      "event_key": "75ac8fd0308b5e0bee2354bd8cccc10de5327ec6f86add5e025b5ae27aabff82",
      "hostname": "lab-pc01",
      "logon_type": 3,
      "provider": "Microsoft-Windows-Security-Auditing",
      "record_id": 2101,
      "source_ip": "192.0.2.10",
      "subject_domain": null,
      "subject_logon_id": null,
      "subject_user": null,
      "target_domain": "lab",
      "target_logon_id": null,
      "target_user": "alice",
      "task_content": null,
      "task_name": null,
      "timestamp": "2026-01-15T09:00:00.000000Z"
    },
    {
      "channel": "Security",
      "event_id": 4625,
      "event_key": "1dfda011dbe127b19aed027b04e313559b3198cb5e6fde29995f0ab39e12e336",
      "hostname": "lab-pc01",
      "logon_type": 3,
      "provider": "Microsoft-Windows-Security-Auditing",
      "record_id": 2102,
      "source_ip": "192.0.2.10",
      "subject_domain": null,
      "subject_logon_id": null,
      "subject_user": null,
      "target_domain": "lab",
      "target_logon_id": null,
      "target_user": "alice",
      "task_content": null,
      "task_name": null,
      "timestamp": "2026-01-15T09:01:00.000000Z"
    },
    {
      "channel": "Security",
      "event_id": 4625,
      "event_key": "1138223c1a0ac56c27fe370dac28bda37ef7d94359d331cb701e7a4b9bc067f2",
      "hostname": "lab-pc01",
      "logon_type": 3,
      "provider": "Microsoft-Windows-Security-Auditing",
      "record_id": 2103,
      "source_ip": "192.0.2.10",
      "subject_domain": null,
      "subject_logon_id": null,
      "subject_user": null,
      "target_domain": "lab",
      "target_logon_id": null,
      "target_user": "alice",
      "task_content": null,
      "task_name": null,
      "timestamp": "2026-01-15T09:02:00.000000Z"
    },
    {
      "channel": "Security",
      "event_id": 4625,
      "event_key": "38851c164e5eb4a1b1e955713ee627f3ef355ebf76be35fe37dcd5ef9cc57386",
      "hostname": "lab-pc01",
      "logon_type": 3,
      "provider": "Microsoft-Windows-Security-Auditing",
      "record_id": 2104,
      "source_ip": "192.0.2.10",
      "subject_domain": null,
      "subject_logon_id": null,
      "subject_user": null,
      "target_domain": "lab",
      "target_logon_id": null,
      "target_user": "alice",
      "task_content": null,
      "task_name": null,
      "timestamp": "2026-01-15T09:03:00.000000Z"
    },
    {
      "channel": "Security",
      "event_id": 4625,
      "event_key": "7c7e218149ab589f0137d1dd3e3141a355ac674b0ad89fc7208ec6724348e599",
      "hostname": "lab-pc01",
      "logon_type": 3,
      "provider": "Microsoft-Windows-Security-Auditing",
      "record_id": 2105,
      "source_ip": "192.0.2.10",
      "subject_domain": null,
      "subject_logon_id": null,
      "subject_user": null,
      "target_domain": "lab",
      "target_logon_id": null,
      "target_user": "alice",
      "task_content": null,
      "task_name": null,
      "timestamp": "2026-01-15T09:04:00.000000Z"
    },
    {
      "channel": "Security",
      "event_id": 4624,
      "event_key": "e8bd2740332db23f4601cfbacbd90d5b2e441e1214f23be5f75474a675fcfd01",
      "hostname": "lab-pc01",
      "logon_type": 3,
      "provider": "Microsoft-Windows-Security-Auditing",
      "record_id": 2106,
      "source_ip": "192.0.2.10",
      "subject_domain": null,
      "subject_logon_id": null,
      "subject_user": null,
      "target_domain": "lab",
      "target_logon_id": "0x1234",
      "target_user": "alice",
      "task_content": null,
      "task_name": null,
      "timestamp": "2026-01-15T09:05:00.000000Z"
    },
    {
      "channel": "Security",
      "event_id": 4698,
      "event_key": "285ce62c6ebca44e31a5ec6de3a66a79aa201eb4c86144d628980ad81a0e39e2",
      "hostname": "lab-pc01",
      "logon_type": null,
      "provider": "Microsoft-Windows-Security-Auditing",
      "record_id": 2107,
      "source_ip": null,
      "subject_domain": "lab",
      "subject_logon_id": "0x1234",
      "subject_user": "alice",
      "target_domain": null,
      "target_logon_id": null,
      "target_user": null,
      "task_content": "<Task version=\"1.2\"><Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo SHIELD56_SYNTHETIC_MARKER&gt; \"%TEMP%\\shield56_synthetic_marker.txt\"</Arguments></Exec></Actions></Task>",
      "task_name": "\\Shield56\\SyntheticSequenceMarker",
      "timestamp": "2026-01-15T09:08:00.000000Z"
    }
  ],
  "scope": "All finding-supporting distinct events"
}
```

## Case conclusion — saved analyst judgment

```json
{
  "disposition": "needs investigation",
  "saved_at_utc": null,
  "status": "not saved",
  "text": ""
}
```

## Finding 1 — R1

```json
{
  "account": "lab\\alice",
  "analyst_checks": [
    "Verify the source IP, target account, logon type, and failure status in the original events.",
    "Compare expected user activity, authentication infrastructure, and endpoint logs."
  ],
  "analyst_note": null,
  "benign_explanations": [
    "A user may be retrying an outdated or mistyped password.",
    "A service, mapped drive, or scheduled client may retain stale credentials."
  ],
  "explanation": "5 distinct failed-logon events support this episode. At least 5 occurred within an inclusive rolling 5-minute window. Overlapping qualifying windows share evidence and form one episode; this may reflect retries or other causes.",
  "finding_id": "R1-db715d04005f598ed152175425060760b252e1cac8009678aefd6fab2bbcdadf",
  "first_utc": "2026-01-15T09:00:00+00:00",
  "hostname": "lab-pc01",
  "last_utc": "2026-01-15T09:04:00+00:00",
  "related_finding_ids": [],
  "rule_id": "R1",
  "rule_name": "Repeated failed logons",
  "rule_version": "1.0.0",
  "severity": "Medium",
  "severity_rationale": "A concentrated authentication failure episode warrants review; it does not establish compromise.",
  "source_ip": "192.0.2.10",
  "supporting_event_keys": [
    "75ac8fd0308b5e0bee2354bd8cccc10de5327ec6f86add5e025b5ae27aabff82",
    "1dfda011dbe127b19aed027b04e313559b3198cb5e6fde29995f0ab39e12e336",
    "1138223c1a0ac56c27fe370dac28bda37ef7d94359d331cb701e7a4b9bc067f2",
    "38851c164e5eb4a1b1e955713ee627f3ef355ebf76be35fe37dcd5ef9cc57386",
    "7c7e218149ab589f0137d1dd3e3141a355ac674b0ad89fc7208ec6724348e599"
  ],
  "supporting_event_references": [
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:13",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:14",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:15",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:16",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:17"
  ]
}
```

## Finding 2 — R2

```json
{
  "account": "lab\\alice",
  "analyst_checks": [
    "Confirm the success belongs to the expected user, source address, host, and logon type.",
    "Review MFA/identity-provider records, endpoint activity, and the target logon session."
  ],
  "analyst_note": null,
  "benign_explanations": [
    "The legitimate user may have corrected a password after repeated attempts.",
    "A service credential may have been updated during troubleshooting."
  ],
  "explanation": "A successful logon followed the final failed event in the episode, within 10 minutes, with matching host, target account/domain, source IP and compatible logon type. The earliest eligible success is selected; legitimate password correction remains possible.",
  "finding_id": "R2-51d98b0c5c015cd7f3cba0ce2c6eb7c460ee44466c02f00d0c8ec9cb915d3189",
  "first_utc": "2026-01-15T09:00:00+00:00",
  "hostname": "lab-pc01",
  "last_utc": "2026-01-15T09:05:00+00:00",
  "related_finding_ids": [
    "R1-db715d04005f598ed152175425060760b252e1cac8009678aefd6fab2bbcdadf"
  ],
  "rule_id": "R2",
  "rule_name": "Successful logon following repeated failures",
  "rule_version": "1.0.0",
  "severity": "High",
  "severity_rationale": "A compatible success after repeated failures raises investigation priority; successful authentication is not proof of account compromise.",
  "source_ip": "192.0.2.10",
  "supporting_event_keys": [
    "75ac8fd0308b5e0bee2354bd8cccc10de5327ec6f86add5e025b5ae27aabff82",
    "1dfda011dbe127b19aed027b04e313559b3198cb5e6fde29995f0ab39e12e336",
    "1138223c1a0ac56c27fe370dac28bda37ef7d94359d331cb701e7a4b9bc067f2",
    "38851c164e5eb4a1b1e955713ee627f3ef355ebf76be35fe37dcd5ef9cc57386",
    "7c7e218149ab589f0137d1dd3e3141a355ac674b0ad89fc7208ec6724348e599",
    "e8bd2740332db23f4601cfbacbd90d5b2e441e1214f23be5f75474a675fcfd01"
  ],
  "supporting_event_references": [
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:13",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:14",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:15",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:16",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:17",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:18"
  ]
}
```

## Finding 3 — R3

```json
{
  "account": "lab\\alice",
  "analyst_checks": [
    "Inspect the task definition, executable, arguments, author, trigger, and authorization without executing it.",
    "Check logoff/reboot/session-reuse evidence and process-creation or task-scheduler logs.",
    "Seek independent evidence before concluding compromise or malicious persistence."
  ],
  "analyst_note": null,
  "benign_explanations": [
    "An authorized administrator or installer may legitimately create a scheduled task.",
    "A maintenance or troubleshooting workflow may follow authentication retries."
  ],
  "explanation": "1 distinct task creation event(s) followed suspicious authentication within 15 minutes. Host and subject account/domain match the successful logon's target account, and both use the same nonzero logon ID. The displayed source IP belongs to authentication, not necessarily the task. No intervening reuse of this host-scoped session ID is visible. Session IDs can be reused; compromise and malicious persistence require further evidence.",
  "finding_id": "R3-76a07ac57291092ab410d13ecdd760f3a5e166c198ea482f1561d9c5e108d346",
  "first_utc": "2026-01-15T09:00:00+00:00",
  "hostname": "lab-pc01",
  "last_utc": "2026-01-15T09:08:00+00:00",
  "related_finding_ids": [
    "R1-db715d04005f598ed152175425060760b252e1cac8009678aefd6fab2bbcdadf",
    "R2-51d98b0c5c015cd7f3cba0ce2c6eb7c460ee44466c02f00d0c8ec9cb915d3189"
  ],
  "rule_id": "R3",
  "rule_name": "Task creation following suspicious authentication",
  "rule_version": "1.0.0",
  "severity": "High",
  "severity_rationale": "A task creation linked by host, account, time, and session to correlated authentication needs review; malicious persistence remains a hypothesis.",
  "source_ip": "192.0.2.10",
  "supporting_event_keys": [
    "75ac8fd0308b5e0bee2354bd8cccc10de5327ec6f86add5e025b5ae27aabff82",
    "1dfda011dbe127b19aed027b04e313559b3198cb5e6fde29995f0ab39e12e336",
    "1138223c1a0ac56c27fe370dac28bda37ef7d94359d331cb701e7a4b9bc067f2",
    "38851c164e5eb4a1b1e955713ee627f3ef355ebf76be35fe37dcd5ef9cc57386",
    "7c7e218149ab589f0137d1dd3e3141a355ac674b0ad89fc7208ec6724348e599",
    "e8bd2740332db23f4601cfbacbd90d5b2e441e1214f23be5f75474a675fcfd01",
    "285ce62c6ebca44e31a5ec6de3a66a79aa201eb4c86144d628980ad81a0e39e2"
  ],
  "supporting_event_references": [
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:13",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:14",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:15",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:16",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:17",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:18",
    "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:19"
  ]
}
```

## Previous-finding notes — not current findings

```json
{}
```

## Analyst observations, hypotheses and alternative explanations

```json
{
  "alternative_explanations": "",
  "hypotheses": "",
  "observations": "",
  "saved_at_utc": null
}
```

## Recommended containment and recovery actions

```json
{
  "actions": [
    {
      "category": "containment",
      "description": "Proposed for authorized review; no action recorded.",
      "performed_at_utc": null,
      "performed_record": "",
      "status": "proposed"
    },
    {
      "category": "recovery",
      "description": "Proposed for authorized review; no action recorded.",
      "performed_at_utc": null,
      "performed_record": "",
      "status": "proposed"
    }
  ],
  "status_policy": "Proposed only unless the analyst records performed. Performed status is an analyst assertion, not independent verification. performed_at_utc is when that assertion was recorded."
}
```

## Validation errors — rejected source records

```json
[]
```

## Limitations and handling

```json
[
  "Findings are hypotheses requiring analyst review, not proof of compromise or malicious persistence.",
  "Severity is investigation priority; analyst dispositions are separate judgments.",
  "Missing events, clock skew and reused host-scoped session IDs may affect correlations.",
  "A hash supports integrity checking from the time of hashing; it does not prove earlier authenticity, completeness or chain of custody.",
  "Only saved notes and conclusions are included; unsaved drafts are excluded.",
  "This report is not a restorable case backup. Preserve original exports separately.",
  "Exports contain sensitive evidence and analyst text; protect downloaded copies."
]
```

## Evidence that would help resolve uncertainty

```json
[
  "Complete Security log exports with retention, audit-policy, host-clock and timezone context.",
  "User or administrator authorization and change records.",
  "Identity-provider/MFA records, endpoint process events and task-scheduler logs.",
  "Logoff/reboot records to evaluate reuse of host-scoped logon IDs."
]
```

## Evidence-handling record

```json
[
  {
    "at_utc": "2026-11-18T08:12:45.322346+00:00",
    "byte_count": 2634,
    "filename": "suspicious_sequence.synthetic.csv",
    "hash_scope": "Exact original bytes before parsing",
    "import_id": "import_1",
    "operation": "import",
    "result": "parsed",
    "sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780"
  }
]
```

## Evidence 1 — normalized event and original sources

```json
{
  "event_key": "8a656ac994b8b64eabd92b7d525fb738c9d799d6f9e21929b9594650424becea",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2001,
    "source_ip": "192.0.2.20",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5000",
    "target_user": "bob",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:01:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 2,
      "line_start": 2,
      "occurrence_id": "import_1:record:1",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2001",
        "source_ip": "192.0.2.20",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5000",
        "target_user": "bob",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:01:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:01:00Z",
      "record_position": 1,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:01:00Z,4624,LAB-PC02,2001,Microsoft-Windows-Security-Auditing,Security,bob,LAB,,,192.0.2.20,3,0x5000,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:1"
    }
  ]
}
```

## Evidence 2 — normalized event and original sources

```json
{
  "event_key": "a7b7cf2650f61d4faeaf36eacbbc7a92f2db85ae9ab456f751256be66ee74252",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2002,
    "source_ip": "192.0.2.21",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5001",
    "target_user": "dave",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:11:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 3,
      "line_start": 3,
      "occurrence_id": "import_1:record:2",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2002",
        "source_ip": "192.0.2.21",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5001",
        "target_user": "dave",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:11:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:11:00Z",
      "record_position": 2,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:11:00Z,4624,LAB-PC02,2002,Microsoft-Windows-Security-Auditing,Security,dave,LAB,,,192.0.2.21,3,0x5001,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:2"
    }
  ]
}
```

## Evidence 3 — normalized event and original sources

```json
{
  "event_key": "e82b7918a6f0571b9725abd8d176ebad4df247419bf7591079f7b29f77ba1a14",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2003,
    "source_ip": "192.0.2.20",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5002",
    "target_user": "dave",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:16:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 4,
      "line_start": 4,
      "occurrence_id": "import_1:record:3",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2003",
        "source_ip": "192.0.2.20",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5002",
        "target_user": "dave",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:16:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:16:00Z",
      "record_position": 3,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:16:00Z,4624,LAB-PC02,2003,Microsoft-Windows-Security-Auditing,Security,dave,LAB,,,192.0.2.20,3,0x5002,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:3"
    }
  ]
}
```

## Evidence 4 — normalized event and original sources

```json
{
  "event_key": "3dc1942b390f9fd9d45d938abe7fd941b7291cbc0ef15a4e21b64984cd4940f6",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2004,
    "source_ip": "192.0.2.20",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5003",
    "target_user": "bob",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:26:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 5,
      "line_start": 5,
      "occurrence_id": "import_1:record:4",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2004",
        "source_ip": "192.0.2.20",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5003",
        "target_user": "bob",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:26:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:26:00Z",
      "record_position": 4,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:26:00Z,4624,LAB-PC02,2004,Microsoft-Windows-Security-Auditing,Security,bob,LAB,,,192.0.2.20,3,0x5003,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:4"
    }
  ]
}
```

## Evidence 5 — normalized event and original sources

```json
{
  "event_key": "a600ec36c7f57e82638940d00e37dbcae3d192f7f4a902a18a5accccec4b175a",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2005,
    "source_ip": "192.0.2.21",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5004",
    "target_user": "dave",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:32:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 6,
      "line_start": 6,
      "occurrence_id": "import_1:record:5",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2005",
        "source_ip": "192.0.2.21",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5004",
        "target_user": "dave",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:32:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:32:00Z",
      "record_position": 5,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:32:00Z,4624,LAB-PC02,2005,Microsoft-Windows-Security-Auditing,Security,dave,LAB,,,192.0.2.21,3,0x5004,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:5"
    }
  ]
}
```

## Evidence 6 — normalized event and original sources

```json
{
  "event_key": "bb1d0b42fc28c88d6eadd2607fad86549c88f89b8a0300ea0ed84d52c9333507",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2006,
    "source_ip": "192.0.2.21",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5005",
    "target_user": "dave",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:43:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 7,
      "line_start": 7,
      "occurrence_id": "import_1:record:6",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2006",
        "source_ip": "192.0.2.21",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5005",
        "target_user": "dave",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:43:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:43:00Z",
      "record_position": 6,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:43:00Z,4624,LAB-PC02,2006,Microsoft-Windows-Security-Auditing,Security,dave,LAB,,,192.0.2.21,3,0x5005,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:6"
    }
  ]
}
```

## Evidence 7 — normalized event and original sources

```json
{
  "event_key": "7292fc315c675bb897dab428699e2b6b2586c450d6269972b6b5e4c65b8e1c74",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2007,
    "source_ip": "192.0.2.20",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5006",
    "target_user": "carol",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:51:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 8,
      "line_start": 8,
      "occurrence_id": "import_1:record:7",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2007",
        "source_ip": "192.0.2.20",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5006",
        "target_user": "carol",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:51:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:51:00Z",
      "record_position": 7,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:51:00Z,4624,LAB-PC02,2007,Microsoft-Windows-Security-Auditing,Security,carol,LAB,,,192.0.2.20,3,0x5006,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:7"
    }
  ]
}
```

## Evidence 8 — normalized event and original sources

```json
{
  "event_key": "34fb9b9f16b126473d16477fa3d98edca4e77aa0fb08cdce6b706323a554a8ba",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2008,
    "source_ip": "192.0.2.21",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5007",
    "target_user": "dave",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T07:59:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 9,
      "line_start": 9,
      "occurrence_id": "import_1:record:8",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2008",
        "source_ip": "192.0.2.21",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5007",
        "target_user": "dave",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T07:59:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T07:59:00Z",
      "record_position": 8,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T07:59:00Z,4624,LAB-PC02,2008,Microsoft-Windows-Security-Auditing,Security,dave,LAB,,,192.0.2.21,3,0x5007,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:8"
    }
  ]
}
```

## Evidence 9 — normalized event and original sources

```json
{
  "event_key": "bad8bdf748ba2f2c765202d5949159f0fdec8530f78f606f9477c7a6a0712428",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2009,
    "source_ip": "192.0.2.20",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5008",
    "target_user": "dave",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T08:04:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 10,
      "line_start": 10,
      "occurrence_id": "import_1:record:9",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2009",
        "source_ip": "192.0.2.20",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5008",
        "target_user": "dave",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T08:04:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T08:04:00Z",
      "record_position": 9,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T08:04:00Z,4624,LAB-PC02,2009,Microsoft-Windows-Security-Auditing,Security,dave,LAB,,,192.0.2.20,3,0x5008,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:9"
    }
  ]
}
```

## Evidence 10 — normalized event and original sources

```json
{
  "event_key": "80952ce1b88e675b11e7774ac69f1bb1634d75686f4acaad29dad7ad80c17319",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2010,
    "source_ip": "192.0.2.21",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x5009",
    "target_user": "carol",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T08:13:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 11,
      "line_start": 11,
      "occurrence_id": "import_1:record:10",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2010",
        "source_ip": "192.0.2.21",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x5009",
        "target_user": "carol",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T08:13:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T08:13:00Z",
      "record_position": 10,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T08:13:00Z,4624,LAB-PC02,2010,Microsoft-Windows-Security-Auditing,Security,carol,LAB,,,192.0.2.21,3,0x5009,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:10"
    }
  ]
}
```

## Evidence 11 — normalized event and original sources

```json
{
  "event_key": "974b18d9a08fb04439ed28fc90909ab6cf04f444860feef37d5de91daefdab26",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2011,
    "source_ip": "192.0.2.20",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x500a",
    "target_user": "bob",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T08:21:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 12,
      "line_start": 12,
      "occurrence_id": "import_1:record:11",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2011",
        "source_ip": "192.0.2.20",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x500a",
        "target_user": "bob",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T08:21:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T08:21:00Z",
      "record_position": 11,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T08:21:00Z,4624,LAB-PC02,2011,Microsoft-Windows-Security-Auditing,Security,bob,LAB,,,192.0.2.20,3,0x500a,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:11"
    }
  ]
}
```

## Evidence 12 — normalized event and original sources

```json
{
  "event_key": "0366134746d669464fa7e57d2595543fcb8cf28f948f1f480e3bb6e53f9c7e79",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc02",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2012,
    "source_ip": "192.0.2.21",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x500b",
    "target_user": "bob",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T08:30:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 13,
      "line_start": 13,
      "occurrence_id": "import_1:record:12",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC02",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2012",
        "source_ip": "192.0.2.21",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x500b",
        "target_user": "bob",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T08:30:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T08:30:00Z",
      "record_position": 12,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T08:30:00Z,4624,LAB-PC02,2012,Microsoft-Windows-Security-Auditing,Security,bob,LAB,,,192.0.2.21,3,0x500b,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:12"
    }
  ]
}
```

## Evidence 13 — normalized event and original sources

```json
{
  "event_key": "75ac8fd0308b5e0bee2354bd8cccc10de5327ec6f86add5e025b5ae27aabff82",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4625,
    "hostname": "lab-pc01",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2101,
    "source_ip": "192.0.2.10",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": null,
    "target_user": "alice",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T09:00:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 14,
      "line_start": 14,
      "occurrence_id": "import_1:record:13",
      "original_fields": {
        "channel": "Security",
        "event_id": "4625",
        "hostname": "LAB-PC01",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2101",
        "source_ip": "192.0.2.10",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "",
        "target_user": "alice",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T09:00:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T09:00:00Z",
      "record_position": 13,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T09:00:00Z,4625,LAB-PC01,2101,Microsoft-Windows-Security-Auditing,Security,alice,LAB,,,192.0.2.10,3,,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:13"
    }
  ]
}
```

## Evidence 14 — normalized event and original sources

```json
{
  "event_key": "1dfda011dbe127b19aed027b04e313559b3198cb5e6fde29995f0ab39e12e336",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4625,
    "hostname": "lab-pc01",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2102,
    "source_ip": "192.0.2.10",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": null,
    "target_user": "alice",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T09:01:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 15,
      "line_start": 15,
      "occurrence_id": "import_1:record:14",
      "original_fields": {
        "channel": "Security",
        "event_id": "4625",
        "hostname": "LAB-PC01",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2102",
        "source_ip": "192.0.2.10",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "",
        "target_user": "alice",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T09:01:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T09:01:00Z",
      "record_position": 14,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T09:01:00Z,4625,LAB-PC01,2102,Microsoft-Windows-Security-Auditing,Security,alice,LAB,,,192.0.2.10,3,,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:14"
    }
  ]
}
```

## Evidence 15 — normalized event and original sources

```json
{
  "event_key": "1138223c1a0ac56c27fe370dac28bda37ef7d94359d331cb701e7a4b9bc067f2",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4625,
    "hostname": "lab-pc01",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2103,
    "source_ip": "192.0.2.10",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": null,
    "target_user": "alice",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T09:02:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 16,
      "line_start": 16,
      "occurrence_id": "import_1:record:15",
      "original_fields": {
        "channel": "Security",
        "event_id": "4625",
        "hostname": "LAB-PC01",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2103",
        "source_ip": "192.0.2.10",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "",
        "target_user": "alice",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T09:02:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T09:02:00Z",
      "record_position": 15,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T09:02:00Z,4625,LAB-PC01,2103,Microsoft-Windows-Security-Auditing,Security,alice,LAB,,,192.0.2.10,3,,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:15"
    }
  ]
}
```

## Evidence 16 — normalized event and original sources

```json
{
  "event_key": "38851c164e5eb4a1b1e955713ee627f3ef355ebf76be35fe37dcd5ef9cc57386",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4625,
    "hostname": "lab-pc01",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2104,
    "source_ip": "192.0.2.10",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": null,
    "target_user": "alice",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T09:03:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 17,
      "line_start": 17,
      "occurrence_id": "import_1:record:16",
      "original_fields": {
        "channel": "Security",
        "event_id": "4625",
        "hostname": "LAB-PC01",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2104",
        "source_ip": "192.0.2.10",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "",
        "target_user": "alice",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T09:03:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T09:03:00Z",
      "record_position": 16,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T09:03:00Z,4625,LAB-PC01,2104,Microsoft-Windows-Security-Auditing,Security,alice,LAB,,,192.0.2.10,3,,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:16"
    }
  ]
}
```

## Evidence 17 — normalized event and original sources

```json
{
  "event_key": "7c7e218149ab589f0137d1dd3e3141a355ac674b0ad89fc7208ec6724348e599",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4625,
    "hostname": "lab-pc01",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2105,
    "source_ip": "192.0.2.10",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": null,
    "target_user": "alice",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T09:04:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 18,
      "line_start": 18,
      "occurrence_id": "import_1:record:17",
      "original_fields": {
        "channel": "Security",
        "event_id": "4625",
        "hostname": "LAB-PC01",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2105",
        "source_ip": "192.0.2.10",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "",
        "target_user": "alice",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T09:04:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T09:04:00Z",
      "record_position": 17,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T09:04:00Z,4625,LAB-PC01,2105,Microsoft-Windows-Security-Auditing,Security,alice,LAB,,,192.0.2.10,3,,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:17"
    }
  ]
}
```

## Evidence 18 — normalized event and original sources

```json
{
  "event_key": "e8bd2740332db23f4601cfbacbd90d5b2e441e1214f23be5f75474a675fcfd01",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4624,
    "hostname": "lab-pc01",
    "logon_type": 3,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2106,
    "source_ip": "192.0.2.10",
    "subject_domain": null,
    "subject_logon_id": null,
    "subject_user": null,
    "target_domain": "lab",
    "target_logon_id": "0x1234",
    "target_user": "alice",
    "task_content": null,
    "task_name": null,
    "timestamp": "2026-01-15T09:05:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 19,
      "line_start": 19,
      "occurrence_id": "import_1:record:18",
      "original_fields": {
        "channel": "Security",
        "event_id": "4624",
        "hostname": "LAB-PC01",
        "logon_type": "3",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2106",
        "source_ip": "192.0.2.10",
        "subject_domain": "",
        "subject_logon_id": "",
        "subject_user": "",
        "target_domain": "LAB",
        "target_logon_id": "0x1234",
        "target_user": "alice",
        "task_content": "",
        "task_name": "",
        "timestamp": "2026-01-15T09:05:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T09:05:00Z",
      "record_position": 18,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T09:05:00Z,4624,LAB-PC01,2106,Microsoft-Windows-Security-Auditing,Security,alice,LAB,,,192.0.2.10,3,0x1234,,,\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:18"
    }
  ]
}
```

## Evidence 19 — normalized event and original sources

```json
{
  "event_key": "285ce62c6ebca44e31a5ec6de3a66a79aa201eb4c86144d628980ad81a0e39e2",
  "normalized_fields": {
    "channel": "Security",
    "event_id": 4698,
    "hostname": "lab-pc01",
    "logon_type": null,
    "provider": "Microsoft-Windows-Security-Auditing",
    "record_id": 2107,
    "source_ip": null,
    "subject_domain": "lab",
    "subject_logon_id": "0x1234",
    "subject_user": "alice",
    "target_domain": null,
    "target_logon_id": null,
    "target_user": null,
    "task_content": "<Task version=\"1.2\"><Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo SHIELD56_SYNTHETIC_MARKER&gt; \"%TEMP%\\shield56_synthetic_marker.txt\"</Arguments></Exec></Actions></Task>",
    "task_name": "\\Shield56\\SyntheticSequenceMarker",
    "timestamp": "2026-01-15T09:08:00.000000Z"
  },
  "occurrences": [
    {
      "assumed_timezone": null,
      "file_sha256": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780",
      "filename": "suspicious_sequence.synthetic.csv",
      "import_id": "import_1",
      "line_end": 20,
      "line_start": 20,
      "occurrence_id": "import_1:record:19",
      "original_fields": {
        "channel": "Security",
        "event_id": "4698",
        "hostname": "LAB-PC01",
        "logon_type": "",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": "2107",
        "source_ip": "",
        "subject_domain": "LAB",
        "subject_logon_id": "0x1234",
        "subject_user": "alice",
        "target_domain": "",
        "target_logon_id": "",
        "target_user": "",
        "task_content": "<Task version=\"1.2\"><Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo SHIELD56_SYNTHETIC_MARKER&gt; \"%TEMP%\\shield56_synthetic_marker.txt\"</Arguments></Exec></Actions></Task>",
        "task_name": "\\Shield56\\SyntheticSequenceMarker",
        "timestamp": "2026-01-15T09:08:00Z"
      },
      "original_offset": "Z",
      "original_timestamp": "2026-01-15T09:08:00Z",
      "record_position": 19,
      "resolved_offset": "+0000",
      "source_record": "2026-01-15T09:08:00Z,4698,LAB-PC01,2107,Microsoft-Windows-Security-Auditing,Security,,,alice,LAB,,,,0x1234,\\Shield56\\SyntheticSequenceMarker,\"<Task version=\"\"1.2\"\"><Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo SHIELD56_SYNTHETIC_MARKER&gt; \"\"%TEMP%\\shield56_synthetic_marker.txt\"\"</Arguments></Exec></Actions></Task>\"\n",
      "source_ref": "4af7c362bbb1c377077145074af3d034a6e319fe74495163eae7fec1c832c780:record:19"
    }
  ]
}
```
