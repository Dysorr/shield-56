"""Generate clearly labeled synthetic Windows XML from the reproducible scenarios."""
from pathlib import Path
import sys
from xml.sax.saxutils import escape, quoteattr

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.synthetic_scenarios import build_scenarios
from incident_analyzer.xml_parsing import DATA_FIELDS, WINDOWS_NS


def event_xml(row, version=2):
    def value(field):
        return escape(str(row.get(field) if row.get(field) is not None else "-"))
    data = "".join(f'<Data Name={quoteattr(name)}>{value(field)}</Data>'
                   for name, field in DATA_FIELDS.items())
    return (
        f'<Event xmlns="{WINDOWS_NS}"><System>'
        f'<Provider Name={quoteattr(str(row["provider"]))}/>'
        f'<EventID>{value("event_id")}</EventID><Version>{version}</Version>'
        f'<TimeCreated SystemTime={quoteattr(str(row["timestamp"]))}/>'
        f'<EventRecordID>{value("record_id")}</EventRecordID>'
        f'<Channel>{value("channel")}</Channel><Computer>{value("hostname")}</Computer>'
        f'<Security/></System><EventData>{data}</EventData></Event>'
    )


def generate(destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("normal_activity", "suspicious_sequence"):
        rows = build_scenarios()[name]
        text = '<?xml version="1.0" encoding="UTF-8"?>\n<!-- SYNTHETIC ONLY -->\n<Events>\n'
        text += "\n".join(event_xml(row, index % 3) for index, row in enumerate(rows))
        text += "\n</Events>\n"
        (destination / f"{name}.synthetic.xml").write_text(text, encoding="utf-8", newline="\n")
    (destination / "single_event.synthetic.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<!-- SYNTHETIC ONLY -->\n'
        + event_xml(rows[-1], 1), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[1] / "data/synthetic/xml")
