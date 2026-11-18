"""UTF-8 CSV/JSONL parsing with exact source text and physical line locations."""

import csv
import io
import json
from pathlib import Path

from incident_analyzer.models import ParsedRecord
from incident_analyzer.schema import EVENT_FIELDS, REQUIRED_FIELDS

# Bound individual fields by the already enforced maximum file byte size.
csv.field_size_limit(10_000_000)


class FileReadError(ValueError):
    """The file cannot safely be interpreted; no records are accepted."""


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"nonstandard JSON value {value}")


def parse_records(filename, content):
    """Yield records including malformed rows; fail file on decoding/header errors."""
    if Path(filename).suffix.lower() == ".xml":
        from incident_analyzer.xml_parsing import parse_xml
        yield from parse_xml(content)
        return
    try:
        text = content.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as error:
        raise FileReadError(f"Unreadable UTF-8 file at byte {error.start + 1}") from error
    if "\x00" in text:
        raise FileReadError("Unreadable text file: NUL bytes are not supported")
    extension = Path(filename).suffix.lower()
    if extension not in (".csv", ".jsonl"):
        raise FileReadError("Unsupported filename extension; use .csv, .jsonl or .xml")
    if not text.strip():
        return
    if extension == ".jsonl":
        for line_number, raw in enumerate(io.StringIO(text, newline=""), 1):
            if not raw.strip():
                continue
            try:
                fields = json.loads(
                    raw, object_pairs_hook=_object_without_duplicate_keys,
                    parse_constant=_reject_constant,
                )
                yield ParsedRecord(line_number, line_number, line_number, raw, fields)
            except (ValueError, RecursionError) as error:
                yield ParsedRecord(
                    line_number, line_number, line_number, raw, None,
                    f"Malformed JSONL: {error}",
                )
        return
    lines = io.StringIO(text, newline="").readlines()
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except (StopIteration, csv.Error) as error:
        raise FileReadError("CSV header at line 1 is missing or malformed") from error
    if (len(set(header)) != len(header) or
            set(REQUIRED_FIELDS) - set(header) or set(header) - set(EVENT_FIELDS)):
        raise FileReadError(
            f"CSV header at line 1: missing required columns "
            f"{sorted(set(REQUIRED_FIELDS) - set(header))}; unknown columns "
            f"{sorted(set(header) - set(EVENT_FIELDS))}; column names must be unique"
        )
    previous_line = reader.line_num
    position = 0
    while True:
        start = previous_line + 1
        try:
            values = next(reader)
            error = None
        except StopIteration:
            return
        except csv.Error as exception:
            values = None
            error = f"Malformed CSV: {exception}. Unclosed quotes may consume the remaining lines."
        end = max(start, reader.line_num)
        previous_line = end
        raw = "".join(lines[start - 1:end])
        if values == []:  # Blank physical lines are not input records.
            continue
        position += 1
        if values is not None and len(values) != len(header):
            error = f"CSV record has {len(values)} cells; header defines {len(header)}"
        fields = dict(zip(header, values)) if values is not None and not error else None
        yield ParsedRecord(position, start, end, raw, fields, error)
