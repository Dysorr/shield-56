"""Typed input contract; source timestamps are preserved and UTC is explicit."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
import re
from typing import Any

EVENT_FIELDS = (
    "timestamp", "event_id", "hostname", "record_id", "provider", "channel",
    "target_user", "target_domain", "subject_user", "subject_domain", "source_ip",
    "logon_type", "target_logon_id", "subject_logon_id", "task_name", "task_content",
)
REQUIRED_FIELDS = ("timestamp", "event_id", "hostname", "record_id", "provider", "channel")
INTEGER_FIELDS = ("event_id", "record_id", "logon_type")
_ISO_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)"
)


class EventValidationError(ValueError):
    """A record violates the documented contract."""


def parse_timestamp(value: str) -> datetime:
    """Require an explicit offset; never assume a timezone for evidence."""
    if not isinstance(value, str) or not _ISO_TIMESTAMP.fullmatch(value):
        raise EventValidationError("timestamp: expected ISO 8601 with explicit timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EventValidationError("timestamp: invalid date, time, or offset") from error
    if parsed.utcoffset() is None:
        raise EventValidationError("timestamp: timezone required")
    return parsed


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    event_id: int
    hostname: str
    record_id: int
    provider: str
    channel: str
    target_user: str | None
    target_domain: str | None
    subject_user: str | None
    subject_domain: str | None
    source_ip: str | None
    logon_type: int | None
    target_logon_id: str | None
    subject_logon_id: str | None
    task_name: str | None
    task_content: str | None

    @classmethod
    def from_mapping(
        cls, record: Mapping[str, Any], *, require_account: bool = True,
    ) -> "SecurityEvent":
        """Validate typed JSON-style fields without guessing account roles."""
        missing = set(EVENT_FIELDS) - record.keys()
        unknown = record.keys() - set(EVENT_FIELDS)
        if missing or unknown:
            raise EventValidationError(
                f"fields: missing={sorted(missing)}, unknown={sorted(unknown)}"
            )
        for field in EVENT_FIELDS:
            value = record[field]
            if value is None:
                if field in REQUIRED_FIELDS:
                    raise EventValidationError(f"{field}: required")
                continue
            if field in INTEGER_FIELDS:
                if type(value) is not int:
                    raise EventValidationError(f"{field}: expected integer")
                minimum = 1 if field == "record_id" else 0
                maximum = (2**64 - 1) if field == "record_id" else 65535
                if not minimum <= value <= maximum:
                    raise EventValidationError(f"{field}: outside supported integer range")
            elif not isinstance(value, str) or not value.strip():
                raise EventValidationError(f"{field}: expected nonempty string or null")
        parse_timestamp(record["timestamp"])
        if record["source_ip"] is not None:
            try:
                ip_address(record["source_ip"])
            except ValueError as error:
                raise EventValidationError("source_ip: expected IPv4/IPv6 address or null") from error
        for field in ("target_logon_id", "subject_logon_id"):
            value = record[field]
            if value is not None and not re.fullmatch(r"0x[0-9a-fA-F]+", value):
                raise EventValidationError(f"{field}: expected 0x-prefixed hexadecimal string")
        account_field = {4624: "target_user", 4625: "target_user", 4698: "subject_user"}.get(
            record["event_id"]
        )
        if require_account and account_field and record[account_field] is None:
            raise EventValidationError(f"{account_field}: required for event {record['event_id']}")
        return cls(**record)

    @property
    def timestamp_utc(self) -> datetime:
        return parse_timestamp(self.timestamp).astimezone(timezone.utc)

    @property
    def source_identity(self) -> tuple[str, str, str, int]:
        """A record ID alone is not unique across Windows hosts/channels."""
        return self.hostname, self.provider, self.channel, self.record_id


def decode_csv_record(row: Mapping[str, str]) -> dict[str, Any]:
    """Decode CSV nulls and integers; leave text (especially IDs) untouched."""
    decoded: dict[str, Any] = dict(row)
    for field, value in row.items():
        if value == "":
            decoded[field] = None
        elif field in INTEGER_FIELDS:
            if not re.fullmatch(r"[0-9]+", value):
                raise EventValidationError(f"{field}: expected unsigned decimal integer")
            decoded[field] = int(value)
    return decoded
