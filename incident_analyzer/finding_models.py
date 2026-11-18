"""Auditable detection outputs; source occurrence metadata never defines finding identity."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from incident_analyzer.models import SourceOccurrence


@dataclass(frozen=True)
class EventEvidence:
    event_key: str
    timestamp_utc: datetime
    event_id: int
    record_id: int
    source_references: tuple[str, ...]
    source_occurrences: tuple[SourceOccurrence, ...]


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    rule_version: str
    rule_name: str
    first_utc: datetime
    last_utc: datetime
    hostname: str
    account: str
    source_ip: str | None
    supporting_event_keys: tuple[str, ...]
    supporting_event_references: tuple[str, ...]
    source_occurrences: tuple[SourceOccurrence, ...]
    explanation: str
    severity: str
    severity_rationale: str
    benign_explanations: tuple[str, ...]
    analyst_checks: tuple[str, ...]
    related_finding_ids: tuple[str, ...]
    supporting_events: tuple[EventEvidence, ...]


@dataclass(frozen=True)
class AnalysisResult:
    configuration: dict[str, Any]
    rule_versions: dict[str, str]
    distinct_events: int
    source_occurrences: int
    findings: tuple[Finding, ...]
    exclusions: dict[str, int]
