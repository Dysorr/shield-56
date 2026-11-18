"""Windows XML adapter using Expat with all DTD/entity processing forbidden."""

import re
from xml.parsers import expat

from incident_analyzer.models import ParsedRecord
from incident_analyzer.schema import EVENT_FIELDS

WINDOWS_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
DATA_FIELDS = {
    "TargetUserName": "target_user", "TargetDomainName": "target_domain",
    "SubjectUserName": "subject_user", "SubjectDomainName": "subject_domain",
    "IpAddress": "source_ip", "LogonType": "logon_type",
    "TargetLogonId": "target_logon_id", "SubjectLogonId": "subject_logon_id",
    "TaskName": "task_name", "TaskContent": "task_content",
}


def parse_xml(content):
    from incident_analyzer.parsing import FileReadError
    # Decode supported XML encodings explicitly, retaining original bytes in FileImport.
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    elif content.startswith(b"\x00<"):
        encoding = "utf-16-be"
    elif content.startswith(b"<\x00"):
        encoding = "utf-16-le"
    else:
        declaration = re.match(br'\s*<\?xml[^>]*encoding=["\']([^"\']+)', content[:256])
        try:
            encoding = declaration.group(1).decode("ascii") if declaration else "utf-8-sig"
        except UnicodeDecodeError as error:
            raise FileReadError("Invalid XML encoding declaration") from error
        if encoding.lower() not in ("utf-8", "utf-8-sig", "iso-8859-1", "windows-1252", "us-ascii"):
            raise FileReadError(f"Unsupported XML encoding: {encoding}")
    try:
        text = content.decode(encoding)
    except (UnicodeError, LookupError) as error:
        raise FileReadError(f"Unreadable XML encoding: {error}") from error
    # Expat offsets now refer to this UTF-8 buffer, independent of original encoding.
    text = re.sub(r'(<\?xml[^>]*encoding=)["\'][^"\']+["\']', r'\1"UTF-8"', text, count=1)
    buffer = text.encode("utf-8")
    parser = expat.ParserCreate(namespace_separator="|")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack, records = [], []
    start_byte = start_line = 0

    def forbid(*args):
        raise FileReadError("Forbidden XML DTD/entity declaration; external entities are disabled")

    parser.StartDoctypeDeclHandler = forbid
    parser.EntityDeclHandler = forbid
    parser.ExternalEntityRefHandler = forbid

    def local(name):
        parts = name.rsplit("|", 1)
        if len(parts) == 2 and parts[0] != WINDOWS_NS:
            raise FileReadError("Unexpected XML namespace; expected Windows event XML")
        return parts[-1]

    def start(name, attrs):
        nonlocal start_byte, start_line
        tag = local(name)
        if len(stack) > 64:
            raise FileReadError("XML nesting exceeds safety limit of 64")
        if not stack and tag not in ("Event", "Events"):
            raise FileReadError("XML root must be Event or Events")
        if len(stack) == 1 and stack[0]["name"] == "Events" and tag != "Event":
            raise FileReadError("Events root may contain only Event elements")
        if tag == "Event":
            if stack and not (len(stack) == 1 and stack[0]["name"] == "Events"):
                raise FileReadError("Nested Event elements are not supported")
            if len(records) >= 50_000:
                from incident_analyzer.ingestion import ImportLimitError
                raise ImportLimitError("50,000 input-record limit exceeded; batch not imported")
            start_byte, start_line = parser.CurrentByteIndex, parser.CurrentLineNumber
        node = {"name": tag, "qualified_name": name, "attributes": dict(attrs), "text": "", "children": []}
        if stack:
            stack[-1]["children"].append(node)
        stack.append(node)

    def end(name):
        node = stack.pop()
        if local(name) != "Event":
            return
        end_index = parser.CurrentByteIndex
        opening_end = buffer.index(b">", start_byte) + 1
        if buffer[start_byte:opening_end].rstrip().endswith(b"/>"):
            end_index = opening_end
        elif buffer[end_index:end_index + 2] == b"</":
            end_index = buffer.index(b">", end_index) + 1
        raw = buffer[start_byte:end_index].decode("utf-8")
        fields = {key: None for key in EVENT_FIELDS}
        error = None
        try:
            def child(parent, name):
                matches = [n for n in parent["children"] if n["name"] == name]
                if len(matches) > 1:
                    raise ValueError(f"Duplicate XML {name} element")
                return matches[0] if matches else {"text": "", "attributes": {}, "children": []}
            def clean(value):
                return None if value is None or value.strip() in ("", "-") else value
            system = child(node, "System")
            for xml_name, field in (("EventID", "event_id"), ("EventRecordID", "record_id"),
                                    ("Computer", "hostname"), ("Channel", "channel")):
                fields[field] = clean(child(system, xml_name)["text"])
            fields["timestamp"] = clean(child(system, "TimeCreated")["attributes"].get("SystemTime"))
            fields["provider"] = clean(child(system, "Provider")["attributes"].get("Name"))
            seen = set()
            for data in child(node, "EventData")["children"]:
                name = data["attributes"].get("Name")
                if name in DATA_FIELDS:
                    if name in seen:
                        raise ValueError(f"Duplicate named EventData field {name}")
                    seen.add(name)
                    fields[DATA_FIELDS[name]] = clean(data["text"])
            for field in ("event_id", "record_id", "logon_type"):
                if fields[field] is not None:
                    fields[field] = int(fields[field].strip(), 10)
        except ValueError as exc:
            error = str(exc)
        records.append(ParsedRecord(len(records) + 1, start_line, parser.CurrentLineNumber,
                                    raw, fields, error, node))
        if stack:
            stack[-1]["children"].pop()  # Do not retain two copies of every event tree.

    def chars(value):
        if stack:
            stack[-1]["text"] += value
    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(buffer, True)
    except expat.ExpatError as error:
        raise FileReadError(f"Malformed XML at line {error.lineno}, column {error.offset}: {error}") from error
    # Whole-document validation before yielding prevents partial malformed imports.
    yield from records
