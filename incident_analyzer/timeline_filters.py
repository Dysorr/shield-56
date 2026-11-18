"""Pure display filtering and bounded UTC event-volume aggregation, never detection input."""

from collections import Counter
from datetime import date, datetime, timedelta, timezone
import math

from incident_analyzer.models import NormalizedEvent


def account_label(event: NormalizedEvent) -> str:
    """Display/correlation actor: target for logons, subject for task creation."""
    role = "subject" if event.fields["event_id"] == 4698 else "target"
    user, domain = event.fields.get(f"{role}_user"), event.fields.get(f"{role}_domain")
    if user is None:
        return "(missing account)"
    return f"{domain if domain is not None else '(missing domain)'}\\{user}"


def filter_timeline(events, *, start_date: date | None = None, end_date: date | None = None,
                    hosts=(), accounts=(), event_ids=(), source_ips=(), query=""):
    if start_date and end_date and start_date > end_date:
        raise ValueError("UTC start date must be on or before the UTC end date.")
    result = []
    needle = query.casefold().strip()
    selected_ids = {str(value) for value in event_ids}
    for event in events:
        fields = event.fields
        utc_date = event.timestamp_utc.date()
        if (start_date and utc_date < start_date) or (end_date and utc_date > end_date):
            continue
        if hosts and fields["hostname"] not in hosts:
            continue
        if accounts and account_label(event) not in accounts:
            continue
        if selected_ids and str(fields["event_id"]) not in selected_ids:
            continue
        if source_ips and fields["source_ip"] not in source_ips:
            continue
        if needle and not any(needle in str(value).casefold() for value in fields.values() if value is not None):
            continue
        result.append(event)
    return sorted(result, key=lambda event: (event.timestamp_utc, event.event_key))


def volume_bins(events):
    """At most 240 epoch-aligned bins, with zero gaps; exact distinct-event totals.

    Width is whole minutes, chosen from the observed filtered span, not browser
    local time. Only counts and UTC bounds enter the chart.
    """
    if not events:
        return [], 60
    seconds = [event.timestamp_utc.timestamp() for event in events]
    low, high = min(seconds), max(seconds)
    width = max(60, math.ceil((high - low + 1) / (239 * 60)) * 60)
    first, last = math.floor(low / width), math.floor(high / width)
    counts = Counter(math.floor(second / width) for second in seconds)
    rows = []
    for index in range(first, last + 1):
        start = datetime.fromtimestamp(index * width, timezone.utc)
        end = start + timedelta(seconds=width)
        rows.append({
            "UTC bin start": start.isoformat(),
            "UTC bin end": end.isoformat(),
            "Distinct events": counts[index],
        })
    return rows, width
