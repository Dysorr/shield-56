"""End-to-end synthetic scenario check through ingestion, findings and exports."""
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import sys
from zipfile import ZipFile
from io import BytesIO

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from incident_analyzer.case_state import ensure_case
from incident_analyzer.detection import analyze
from incident_analyzer.export_bundle import REPORT_HTML, REPORT_MD, prepare_exports
from incident_analyzer.models import InputFile


def load(state, filename):
    path = ROOT / "data/synthetic" / filename
    state["imports"].import_files([InputFile(path.name, path.read_bytes())])
    return path


def main():
    normal = {}
    ensure_case(normal)
    load(normal, "normal_activity.synthetic.csv")
    normal_result = analyze(normal["imports"])
    assert normal_result.distinct_events == 15 and not normal_result.findings

    case = {}
    ensure_case(case)
    source = load(case, "suspicious_sequence.synthetic.csv")
    result = analyze(case["imports"])
    assert result.distinct_events == 19
    assert Counter(f.rule_id for f in result.findings) == {"R1": 1, "R2": 1, "R3": 1}
    event = next(e for e in case["imports"].analysis_events if e.fields["record_id"] == 2107)
    assert event.occurrences
    occurrence = event.occurrences[0]
    assert occurrence.original_fields["record_id"] == "2107"
    assert occurrence.source_ref.startswith(sha256(source.read_bytes()).hexdigest() + ":")
    case["timeline_display_filters"] = {"event_ids": ["4625"]}
    bundle = prepare_exports(case, generated_at=datetime(2026, 11, 18, tzinfo=timezone.utc))
    assert len(bundle.snapshot["findings"]) == 3
    assert bundle.snapshot["summary"]["distinct_events"] == 19
    markdown = bundle.files[REPORT_MD].decode("utf-8")
    html = bundle.files[REPORT_HTML].decode("utf-8")
    assert "LAB-PC01" in markdown and "2107" in markdown
    assert "alice" in html and "SYNTHETIC DATA" in html
    with ZipFile(BytesIO(bundle.zip_bytes)) as archive:
        assert len(archive.namelist()) == len(bundle.files)
        assert all(archive.read(name) == payload for name, payload in bundle.files.items())
        assert not any(name.startswith("original_evidence/") for name in archive.namelist())
    print("normal_activity: 15 distinct events, 0 findings")
    print("suspicious_sequence: 19 distinct events, R1=1, R2=1, R3=1")
    print("Evidence record 2107 traceability: verified")
    print("Filtered timeline: 5 records; full-case report/findings: 19 events, 3 findings")
    print(f"Prepared {len(bundle.files)} output files; ZIP contents and standalone bytes match.")


if __name__ == "__main__":
    main()
