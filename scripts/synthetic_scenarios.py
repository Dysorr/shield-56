"""Small, reproducible, clearly synthetic Windows Security scenarios.

No code in this module executes task content or reads evaluation answer keys.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import random

from incident_analyzer.schema import EVENT_FIELDS

DEFAULT_SEED = 56
SCENARIO_DATE = "2026-01-15"
MARKER_TASK = (
    '<Task version="1.2"><Actions><Exec><Command>cmd.exe</Command>'
    '<Arguments>/c echo SHIELD56_SYNTHETIC_MARKER&gt; '
    '"%TEMP%\\shield56_synthetic_marker.txt"</Arguments>'
    '</Exec></Actions></Task>'
)


def event(record_id, timestamp, event_id=4624, **fields):
    """Build all schema fields explicitly, leaving non-applicable fields null."""
    record = dict.fromkeys(EVENT_FIELDS)
    record.update(
        timestamp=timestamp, event_id=event_id, hostname="LAB-PC02",
        record_id=record_id, provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
    )
    record.update(fields)
    return record


def background_activity(rng, first_id):
    records = []
    base = datetime(2026, 1, 15, 7, tzinfo=timezone.utc)
    for index in range(12):
        timestamp = base + timedelta(minutes=index * 8 + rng.randint(0, 3))
        records.append(event(
            first_id + index, timestamp.isoformat().replace("+00:00", "Z"),
            target_user=rng.choice(["bob", "carol", "dave"]), target_domain="LAB",
            source_ip=rng.choice(["192.0.2.20", "192.0.2.21"]),
            logon_type=3, target_logon_id=f"0x{0x5000 + index:x}",
        ))
    return records


def normal_activity(rng):
    records = background_activity(rng, 1001)
    for index in range(2):
        records.append(event(
            1101 + index, f"{SCENARIO_DATE}T10:0{index}:00Z", 4625,
            target_user="bob", target_domain="LAB", source_ip="192.0.2.20",
            logon_type=3,
        ))
    records.append(event(
        1201, f"{SCENARIO_DATE}T11:00:00Z", 4698,
        subject_user="lab_admin", subject_domain="LAB", subject_logon_id="0x9000",
        task_name="\\Shield56\\SyntheticRoutineMarker", task_content=MARKER_TASK,
    ))
    return records


def suspicious_sequence(rng):
    records = background_activity(rng, 2001)
    for minute in range(5):
        records.append(event(
            2101 + minute, f"{SCENARIO_DATE}T09:0{minute}:00Z", 4625,
            hostname="LAB-PC01", target_user="alice", target_domain="LAB",
            source_ip="192.0.2.10", logon_type=3,
        ))
    records.append(event(
        2106, f"{SCENARIO_DATE}T09:05:00Z", 4624,
        hostname="LAB-PC01", target_user="alice", target_domain="LAB",
        source_ip="192.0.2.10", logon_type=3, target_logon_id="0x1234",
    ))
    records.append(event(
        2107, f"{SCENARIO_DATE}T09:08:00Z", 4698,
        hostname="LAB-PC01", subject_user="alice", subject_domain="LAB",
        subject_logon_id="0x1234", task_name="\\Shield56\\SyntheticSequenceMarker",
        task_content=MARKER_TASK,
    ))
    return records


def edge_cases():
    def sign_in(record_id, timestamp, **changes):
        fields = dict(target_user="edge_user", target_domain="LAB", logon_type=3,
                      source_ip="192.0.2.30", target_logon_id="0x7777")
        fields.update(changes)
        return event(record_id, timestamp, **fields)

    first = sign_in(3001, f"{SCENARIO_DATE}T12:02:00Z")
    return [
        first,
        sign_in(3002, f"{SCENARIO_DATE}T12:00:00Z"),  # Deliberately out of order.
        deepcopy(first),  # Exact duplicate, not a reused ID with changed content.
        sign_in(3003, "not-a-timestamp"),
        sign_in(3004, f"{SCENARIO_DATE}T12:03:00"),  # No timezone: do not guess.
        sign_in(3005, f"{SCENARIO_DATE}T12:04:00Z", source_ip=None),
        sign_in(3006, f"{SCENARIO_DATE}T15:05:00+03:00"),
        sign_in(3007, f"{SCENARIO_DATE}T07:05:00-05:00"),  # Same UTC instant.
        event(3008, f"{SCENARIO_DATE}T12:06:00Z", 65000),
        event(
            3009, f"{SCENARIO_DATE}T12:07:00Z", 4698,
            subject_user="lab_admin", subject_domain="LAB",
            subject_logon_id="0x8888",
            task_name="<script>alert('SYNTHETIC ONLY')</script>",
            task_content=MARKER_TASK,
        ),
    ]


def build_scenarios(seed=DEFAULT_SEED):
    """Local RNG only: same seed yields identical records, independent of globals."""
    rng = random.Random(seed)
    return {
        "normal_activity": normal_activity(rng),
        "suspicious_sequence": suspicious_sequence(rng),
        "edge_cases": edge_cases(),
    }
