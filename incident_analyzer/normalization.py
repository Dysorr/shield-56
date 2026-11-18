"""Canonical event fields and explicit timezone assumptions, without raw-data loss."""

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from incident_analyzer.schema import (
    EVENT_FIELDS, EventValidationError, SecurityEvent, parse_timestamp,
)

_NAIVE_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?")
_OFFSET = re.compile(r"(Z|[+-]\d{2}:\d{2})$")
CASE_INSENSITIVE_FIELDS = (
    "hostname", "target_user", "target_domain", "subject_user", "subject_domain",
)


def normalize_timestamp(text, assumed_timezone=None):
    """Return UTC, original offset, assumption used, and resolved UTC offset."""
    if not isinstance(text, str):
        raise EventValidationError("timestamp: a nonempty ISO 8601 string is required")
    assumption = None
    original_offset = _OFFSET.search(text)
    if _NAIVE_TIME.fullmatch(text):
        if not assumed_timezone:
            raise EventValidationError(
                "timestamp: timezone missing; explicitly select an IANA timezone and reimport"
            )
        try:
            zone = ZoneInfo(assumed_timezone)
            naive = datetime.fromisoformat(text)
        except (ValueError, ZoneInfoNotFoundError, TypeError) as error:
            raise EventValidationError("timestamp: invalid date or selected IANA timezone") from error
        # Round-trip both folds: zero candidates = spring gap, two = autumn fold.
        candidates = {}
        for fold in (0, 1):
            local = naive.replace(tzinfo=zone, fold=fold)
            utc = local.astimezone(timezone.utc)
            if utc.astimezone(zone).replace(tzinfo=None) == naive:
                candidates[utc] = local
        if not candidates:
            raise EventValidationError(
                "timestamp: nonexistent daylight-saving local time; correct the source timestamp"
            )
        if len(candidates) > 1:
            raise EventValidationError(
                "timestamp: ambiguous daylight-saving local time; supply an explicit UTC offset"
            )
        parsed = next(iter(candidates.values()))
        assumption = assumed_timezone
    else:
        parsed = parse_timestamp(text)
    try:
        utc = parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise EventValidationError("timestamp: UTC conversion outside supported date range") from error
    return utc, original_offset.group(1) if original_offset else None, assumption, parsed.strftime("%z")


def normalize_record(fields, assumed_timezone=None):
    """Normalize all event fields; caller separately retains raw fields and text."""
    if not isinstance(fields, dict):
        raise EventValidationError("record: expected a JSON object or CSV record")
    unknown = set(fields) - set(EVENT_FIELDS)
    if unknown:
        raise EventValidationError(f"fields: unknown={sorted(unknown)}")
    normalized = {name: fields.get(name) for name in EVENT_FIELDS}
    timestamp, offset, assumption, resolved = normalize_timestamp(
        normalized["timestamp"], assumed_timezone,
    )
    normalized["timestamp"] = timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
    for name in CASE_INSENSITIVE_FIELDS:
        if isinstance(normalized[name], str):
            normalized[name] = normalized[name].casefold()
    for name in ("target_logon_id", "subject_logon_id"):
        value = normalized[name]
        if value is not None:
            if not isinstance(value, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
                raise EventValidationError(f"{name}: expected 0x-prefixed hexadecimal string")
            normalized[name] = hex(int(value, 16))
    if normalized["source_ip"] is not None:
        if not isinstance(normalized["source_ip"], str):
            raise EventValidationError("source_ip: expected an address string or null")
        try:
            address = ip_address(normalized["source_ip"])
            normalized["source_ip"] = str(getattr(address, "ipv4_mapped", None) or address)
        except (ValueError, TypeError) as error:
            raise EventValidationError("source_ip: expected IPv4/IPv6 address or null") from error
    # Timeline acceptance does not imply that correlation fields are available.
    SecurityEvent.from_mapping(normalized, require_account=False)
    digest = sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return digest, timestamp, normalized, offset, assumption, resolved
