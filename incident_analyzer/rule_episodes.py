"""Inclusive rolling-window episodes and deterministic authentication selection."""

from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from incident_analyzer.models import NormalizedEvent
from incident_analyzer.rule_config import RuleConfig

GROUP_FIELDS = ("hostname", "target_domain", "target_user", "source_ip")


def authentication_group(event):
    values = tuple(event.fields.get(name) for name in GROUP_FIELDS)
    return values if all(value is not None and value != "" for value in values) else None


@dataclass(frozen=True)
class FailureEpisode:
    group: tuple[str, ...]
    failures: tuple[NormalizedEvent, ...]

    @property
    def final_utc(self):
        return self.failures[-1].timestamp_utc

    @property
    def final_logon_type(self):
        # Same-time final failures must agree; None or mixed types are not guessed.
        types = {
            event.fields["logon_type"] for event in self.failures
            if event.timestamp_utc == self.final_utc
        }
        return next(iter(types)) if len(types) == 1 else None


def failure_episodes(events, config: RuleConfig):
    groups = defaultdict(list)
    for event in events:
        if event.fields["event_id"] == 4625 and (group := authentication_group(event)):
            groups[group].append(event)
    episodes = []
    window = timedelta(minutes=config.failure_window_minutes)
    for group, failures in sorted(groups.items()):
        failures.sort(key=lambda event: (event.timestamp_utc, event.event_key))
        left = 0
        ranges = []
        for right, event in enumerate(failures):
            while event.timestamp_utc - failures[left].timestamp_utc > window:
                left += 1
            if right - left + 1 >= config.failure_threshold:
                if ranges and left <= ranges[-1][1]:
                    ranges[-1] = (ranges[-1][0], right)
                else:
                    ranges.append((left, right))
        episodes.extend(
            FailureEpisode(group, tuple(failures[start:end + 1])) for start, end in ranges
        )
    return tuple(sorted(episodes, key=lambda ep: (ep.final_utc, ep.group)))


def correlated_successes(events, episodes, config: RuleConfig):
    """Assign each success to its nearest compatible episode; keep earliest per episode."""
    indexes = defaultdict(list)
    for number, episode in enumerate(episodes):
        if episode.final_logon_type is not None:
            indexes[(episode.group, episode.final_logon_type)].append(number)
    times = {key: [episodes[index].final_utc for index in numbers]
             for key, numbers in indexes.items()}
    selected = {}
    for success in events:  # Already sorted by UTC and canonical key.
        if success.fields["event_id"] != 4624 or success.fields["logon_type"] is None:
            continue
        group = authentication_group(success)
        key = (group, success.fields["logon_type"])
        position = bisect_left(times.get(key, []), success.timestamp_utc) - 1
        if position < 0:
            continue
        episode_number = indexes[key][position]
        elapsed = success.timestamp_utc - episodes[episode_number].final_utc
        if elapsed <= timedelta(minutes=config.success_window_minutes):
            selected.setdefault(episode_number, success)
    return selected
