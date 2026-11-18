from hashlib import sha256

import pytest

from incident_analyzer.ingestion import ImportSession, ImportLimitError
from incident_analyzer.models import InputFile
from incident_analyzer.detection import analyze
from scripts.generate_xml_fixtures import event_xml, generate
from scripts.synthetic_scenarios import build_scenarios


def load(content):
    session = ImportSession()
    session.import_files([InputFile("synthetic.xml", content)])
    return session


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "iso-8859-1"])
def test_namespaces_versions_encodings_raw_and_roles(encoding):
    rows = build_scenarios()["suspicious_sequence"][-7:]
    body = "<Events>\n" + "\n".join(event_xml(row, i % 3) for i, row in enumerate(rows)) + "\n</Events>"
    content = (f'<?xml version="1.0" encoding="{encoding}"?>' + body).encode(encoding)
    session = load(content)
    assert len(session.events) == 7
    assert [f.rule_id for f in analyze(session).findings] == ["R1", "R2", "R3"]
    assert session.files[0].sha256 == sha256(content).hexdigest()
    task = session.analysis_events[-1]
    assert task.fields["subject_user"] == "alice"
    assert task.fields["target_user"] is None
    assert task.occurrences[0].source_record == event_xml(rows[-1], 0)
    assert task.occurrences[0].original_fields["children"][0]["children"][2]["name"] == "Version"


def test_single_prefixed_namespace_and_placeholders():
    row = build_scenarios()["suspicious_sequence"][-1]
    xml = event_xml(row).replace("<Event xmlns=", "<w:Event xmlns:w=").replace("</Event>", "</w:Event>")
    session = load(xml.encode())
    assert session.files[0].accepted == 1
    assert session.analysis_events[0].fields["source_ip"] is None


@pytest.mark.parametrize("body", [
    b"<Events><Event></Events>", b"",
    b'<!DOCTYPE Events [<!ENTITY x SYSTEM "file:///etc/passwd">]><Events>&x;</Events>',
    b'<!DOCTYPE Events SYSTEM "https://example.invalid/evil.dtd"><Events/>',
    b'<Events xmlns="https://wrong.example"/>',
])
def test_malformed_and_forbidden_documents_fail_without_partial_import(body):
    session = load(body)
    assert session.files[0].file_error
    assert not session.events


def test_missing_fields_are_located_and_empty_root_allowed():
    session = load(b"<Events>\n<Event><System/></Event>\n</Events>")
    assert session.files[0].rejected == 1
    assert session.errors[0].record_position == 1
    assert session.errors[0].line_start == 2
    assert load(b"<Events/>").files[0].input_records == 0
    assert load(b"<Events><Event/></Events>").errors[0].source_record == "<Event/>"


def test_duplicate_and_limits_and_raw_unmapped_fields():
    row = build_scenarios()["normal_activity"][0]
    xml = event_xml(row).replace("</EventData>", '<Data Name="Unmapped">keep me</Data></EventData>')
    session = load(("<Events>" + xml * 2 + "</Events>").encode())
    assert session.files[0].duplicates == 1
    assert "Unmapped" in str(session.analysis_events[0].occurrences[0].original_fields)
    with pytest.raises(ImportLimitError):
        load(b" " * 10_000_001)
    with pytest.raises(ImportLimitError):
        load(b"<Events>" + b"<Event/>" * 50_001 + b"</Events>")


def test_fixture_generation_reproducible(tmp_path):
    generate(tmp_path)
    first = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    generate(tmp_path)
    assert first == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert all(b"SYNTHETIC ONLY" in content for content in first.values())
