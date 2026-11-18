"""Independent scenario-level expectations across all three supported formats."""
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from incident_analyzer.ingestion import ImportSession
from incident_analyzer.models import InputFile
from incident_analyzer.detection import analyze


def run():
    results = []
    for name, count, expected in (
        ("normal_activity", 15, {}), ("suspicious_sequence", 19, {"R1": 1, "R2": 1, "R3": 1}),
    ):
        for extension in ("csv", "jsonl", "xml"):
            path = ROOT / "data/synthetic" / ("xml" if extension == "xml" else "") / f"{name}.synthetic.{extension}"
            session = ImportSession()
            session.import_files([InputFile(path.name, path.read_bytes())])
            actual = dict(Counter(f.rule_id for f in analyze(session).findings))
            assert len(session.events) == count and actual == expected
            session.import_files([InputFile(path.name, path.read_bytes())])
            repeated = dict(Counter(f.rule_id for f in analyze(session).findings))
            assert repeated == expected and len(session.events) == count
            results.append({"scenario": name, "format": extension, "events": count,
                            "expected": expected, "actual": actual, "repeated_import_actual": repeated})
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    run()
