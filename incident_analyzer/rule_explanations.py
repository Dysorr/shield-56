"""Rule names and cautious analyst guidance; severity is priority, not certainty."""

RULE_GUIDANCE = {
    "R1": {
        "name": "Repeated failed logons",
        "severity": "Medium",
        "rationale": "A concentrated authentication failure episode warrants review; it does not establish compromise.",
        "benign": (
            "A user may be retrying an outdated or mistyped password.",
            "A service, mapped drive, or scheduled client may retain stale credentials.",
        ),
        "checks": (
            "Verify the source IP, target account, logon type, and failure status in the original events.",
            "Compare expected user activity, authentication infrastructure, and endpoint logs.",
        ),
    },
    "R2": {
        "name": "Successful logon following repeated failures",
        "severity": "High",
        "rationale": "A compatible success after repeated failures raises investigation priority; successful authentication is not proof of account compromise.",
        "benign": (
            "The legitimate user may have corrected a password after repeated attempts.",
            "A service credential may have been updated during troubleshooting.",
        ),
        "checks": (
            "Confirm the success belongs to the expected user, source address, host, and logon type.",
            "Review MFA/identity-provider records, endpoint activity, and the target logon session.",
        ),
    },
    "R3": {
        "name": "Task creation following suspicious authentication",
        "severity": "High",
        "rationale": "A task creation linked by host, account, time, and session to correlated authentication needs review; malicious persistence remains a hypothesis.",
        "benign": (
            "An authorized administrator or installer may legitimately create a scheduled task.",
            "A maintenance or troubleshooting workflow may follow authentication retries.",
        ),
        "checks": (
            "Inspect the task definition, executable, arguments, author, trigger, and authorization without executing it.",
            "Check logoff/reboot/session-reuse evidence and process-creation or task-scheduler logs.",
            "Seek independent evidence before concluding compromise or malicious persistence.",
        ),
    },
}
