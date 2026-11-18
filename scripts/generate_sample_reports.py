"""Regenerate synthetic example reports for the public portfolio."""
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from incident_analyzer.models import InputFile
from incident_analyzer.reporting import build_exports
from incident_analyzer.case_state import ensure_case


def main():
    source = ROOT / "data/synthetic/suspicious_sequence.synthetic.csv"
    state = {}
    ensure_case(state)
    state["imports"].import_files([InputFile(source.name, source.read_bytes())])
    state["report_judgments"] = {
        "case_title": "Synthetic suspicious-sequence training case",
        "observations": "", "hypotheses": "", "alternative_explanations": "",
        "actions": [
            {"category": "containment", "description": "Proposed for authorized review; no action recorded.",
             "status": "proposed", "performed_at_utc": None, "performed_record": ""},
            {"category": "recovery", "description": "Proposed for authorized review; no action recorded.",
             "status": "proposed", "performed_at_utc": None, "performed_record": ""},
        ],
        "saved_at_utc": None,
    }
    # Timestamp follows the real source import; this preserves a coherent
    # generated sample report rather than backdating the import handling record.
    generated = build_exports(state, datetime.now(timezone.utc))
    output = ROOT / "docs/sample-reports"
    output.mkdir(parents=True, exist_ok=True)
    (output / "synthetic-suspicious-investigation.md").write_text(generated.markdown, encoding="utf-8")
    (output / "synthetic-suspicious-investigation.html").write_text(generated.html, encoding="utf-8")
    print(f"Synthetic sample report generated: {generated.snapshot['summary']['distinct_events']} events, "
          f"{generated.snapshot['summary']['findings']} findings, report ID {generated.snapshot['report_id']}")


if __name__ == "__main__":
    main()
