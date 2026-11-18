"""Host-scoped session correlation with conservative handling of visible ID reuse."""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import timedelta


def nonzero_session(value):
    return value is not None and int(value, 16) != 0


def correlated_tasks(events, selected_successes, config):
    # Include ALL successful logons, not just R2 successes, to detect visible reuse.
    sessions = defaultdict(list)
    for event in events:
        fields = event.fields
        if fields["event_id"] == 4624 and nonzero_session(fields["target_logon_id"]):
            sessions[(fields["hostname"], fields["target_logon_id"])].append(event)
    times = {key: [event.timestamp_utc for event in logons] for key, logons in sessions.items()}
    successes = {event.event_key: episode for episode, event in selected_successes.items()}
    for task in events:
        fields = task.fields
        if fields["event_id"] != 4698 or not nonzero_session(fields["subject_logon_id"]):
            continue
        if fields["subject_user"] is None or fields["subject_domain"] is None:
            continue
        key = (fields["hostname"], fields["subject_logon_id"])
        timeline = times.get(key, [])
        before = bisect_left(timeline, task.timestamp_utc)
        # Equal-time logons cannot be ordered confidently relative to the task.
        if before == 0 or bisect_right(timeline, task.timestamp_utc) != before:
            continue
        position = before - 1
        success = sessions[key][position]
        # Multiple distinct logons at the latest instant are ambiguous even if IDs match.
        if position > 0 and timeline[position - 1] == success.timestamp_utc:
            continue
        if success.event_key not in successes:
            continue
        if (fields["subject_domain"], fields["subject_user"]) != (
            success.fields["target_domain"], success.fields["target_user"],
        ):
            continue
        if task.timestamp_utc - success.timestamp_utc <= timedelta(minutes=config.task_window_minutes):
            yield successes[success.event_key], success, task
