"""Generate Shield 56 synthetic CSV/JSONL fixtures and deterministic metadata."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys

# Support `python scripts/generate_synthetic.py` from any working directory.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from incident_analyzer.schema import EVENT_FIELDS
from scripts.synthetic_scenarios import DEFAULT_SEED, SCENARIO_DATE, build_scenarios


def render_jsonl(records):
    return "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                   for row in records).encode("utf-8")


def render_csv(records):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=EVENT_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue().encode("utf-8")


def generate(output_dir: Path, seed=DEFAULT_SEED):
    """Write fixtures only. The separate answer key is never read or generated."""
    output_dir.mkdir(parents=True, exist_ok=True)
    datasets = {}
    for name, records in build_scenarios(seed).items():
        files = {}
        for extension, renderer in (("csv", render_csv), ("jsonl", render_jsonl)):
            filename = f"{name}.synthetic.{extension}"
            content = renderer(records)
            (output_dir / filename).write_bytes(content)
            files[extension] = {
                "filename": filename, "sha256": hashlib.sha256(content).hexdigest(),
            }
        datasets[name] = {
            "synthetic": True, "record_count": len(records),
            "intentionally_invalid": name == "edge_cases", "files": files,
        }
    manifest = {
        "project": "Shield 56", "synthetic": True, "schema_version": 1,
        "seed": seed, "scenario_date": SCENARIO_DATE, "datasets": datasets,
    }
    (output_dir / "manifest.synthetic.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n",
    )
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Generate SYNTHETIC ONLY Shield 56 evidence")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data/synthetic")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    arguments = parser.parse_args()
    manifest = generate(arguments.output_dir, arguments.seed)
    for name, metadata in manifest["datasets"].items():
        print(f"SYNTHETIC {name}: {metadata['record_count']} records (CSV and JSONL)")


if __name__ == "__main__":
    main()
