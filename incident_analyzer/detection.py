"""Deterministic rules over distinct normalized events, never evaluation answers."""

from dataclasses import asdict
from hashlib import sha256
import json

from incident_analyzer.finding_models import AnalysisResult, EventEvidence, Finding
from incident_analyzer.ingestion import ImportSession
from incident_analyzer.models import NormalizedEvent
from incident_analyzer.rule_config import DEFAULT_CONFIG, RULE_VERSION, RuleConfig
from incident_analyzer.rule_episodes import (
    authentication_group, correlated_successes, failure_episodes,
)
from incident_analyzer.rule_explanations import RULE_GUIDANCE
from incident_analyzer.rule_tasks import correlated_tasks, nonzero_session


def detection_events(session: ImportSession) -> tuple[NormalizedEvent, ...]:
    """Do not count repeated source occurrences as independent event evidence."""
    return session.analysis_events


def _finding(rule_id, support, group, config, explanation, parents=()):
    ordered = tuple(sorted(
        {event.event_key: event for event in support}.values(),
        key=lambda event: (event.timestamp_utc, event.event_key),
    ))
    event_keys = tuple(event.event_key for event in ordered)
    identity = json.dumps({
        "rule": rule_id, "version": RULE_VERSION, "configuration": asdict(config),
        "events": event_keys,
    }, sort_keys=True, separators=(",", ":"))
    finding_id = f"{rule_id}-{sha256(identity.encode()).hexdigest()}"
    occurrences = tuple(sorted(
        (occ for event in ordered for occ in event.occurrences),
        key=lambda occ: (occ.source_ref, occ.import_id, occ.occurrence_id),
    ))
    guidance = RULE_GUIDANCE[rule_id]
    host, domain, user, source_ip = group
    return Finding(
        finding_id=finding_id, rule_id=rule_id, rule_version=RULE_VERSION,
        rule_name=guidance["name"], first_utc=ordered[0].timestamp_utc,
        last_utc=ordered[-1].timestamp_utc, hostname=host, account=f"{domain}\\{user}",
        source_ip=source_ip, supporting_event_keys=event_keys,
        supporting_event_references=tuple(sorted({occ.source_ref for occ in occurrences})),
        source_occurrences=occurrences, explanation=explanation,
        severity=guidance["severity"], severity_rationale=guidance["rationale"],
        benign_explanations=guidance["benign"], analyst_checks=guidance["checks"],
        related_finding_ids=tuple(parents),
        supporting_events=tuple(EventEvidence(
            event.event_key, event.timestamp_utc, event.fields["event_id"],
            event.fields["record_id"],
            tuple(sorted({occ.source_ref for occ in event.occurrences})),
            tuple(event.occurrences),
        ) for event in ordered),
    )


def analyze(session: ImportSession, config: RuleConfig = DEFAULT_CONFIG) -> AnalysisResult:
    """Recompute from current evidence; IDs ignore import order and duplicate sources."""
    events = detection_events(session)
    episodes = failure_episodes(events, config)
    selected = correlated_successes(events, episodes, config)
    findings, r1, r2 = [], {}, {}
    for number, episode in enumerate(episodes):
        finding = _finding(
            "R1", episode.failures, episode.group, config,
            f"{len(episode.failures)} distinct failed-logon events support this episode. "
            f"At least {config.failure_threshold} occurred within an inclusive rolling "
            f"{config.failure_window_minutes}-minute window. Overlapping qualifying windows "
            "share evidence and form one episode; this may reflect retries or other causes.",
        )
        r1[number] = finding
        findings.append(finding)
    for number, success in sorted(selected.items()):
        episode = episodes[number]
        finding = _finding(
            "R2", (*episode.failures, success), episode.group, config,
            "A successful logon followed the final failed event in the episode, "
            f"within {config.success_window_minutes} minutes, with matching host, target "
            "account/domain, source IP and compatible logon type. The earliest eligible "
            "success is selected; legitimate password correction remains possible.",
            (r1[number].finding_id,),
        )
        r2[number] = finding
        findings.append(finding)
    tasks_by_episode = {}
    for number, success, task in correlated_tasks(events, selected, config):
        tasks_by_episode.setdefault(number, []).append(task)
    for number, tasks in sorted(tasks_by_episode.items()):
        episode = episodes[number]
        success = selected[number]
        findings.append(_finding(
            "R3", (*episode.failures, success, *tasks), episode.group, config,
            f"{len(tasks)} distinct task creation event(s) followed suspicious authentication within "
            f"{config.task_window_minutes} minutes. Host and subject account/domain match "
            "the successful logon's target account, and both use the same nonzero logon ID. "
            "The displayed source IP belongs to authentication, not necessarily the task. "
            "No intervening reuse of this host-scoped session ID is visible. Session IDs "
            "can be reused; compromise and malicious persistence require further evidence.",
            (r1[number].finding_id, r2[number].finding_id),
        ))
    exclusions = {
        "R1 failures missing grouping fields": sum(
            event.fields["event_id"] == 4625 and authentication_group(event) is None
            for event in events
        ),
        "R2 successes missing grouping fields or logon type": sum(
            event.fields["event_id"] == 4624 and (
                authentication_group(event) is None or event.fields["logon_type"] is None
            ) for event in events
        ),
        "R3 tasks missing account/domain or nonzero session ID": sum(
            event.fields["event_id"] == 4698 and (
                event.fields["subject_user"] is None or event.fields["subject_domain"] is None
                or not nonzero_session(event.fields["subject_logon_id"])
            ) for event in events
        ),
    }
    return AnalysisResult(
        configuration=asdict(config), rule_versions={rule: RULE_VERSION for rule in RULE_GUIDANCE},
        distinct_events=len(events), source_occurrences=sum(len(event.occurrences) for event in events),
        findings=tuple(sorted(findings, key=lambda finding: (finding.first_utc, finding.rule_id, finding.finding_id))),
        exclusions=exclusions,
    )
