"""Reproducible 10,000-event SYNTHETIC workload; timings are local observations."""
from collections import Counter
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import random
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.synthetic_scenarios import build_scenarios
from scripts.generate_synthetic import render_jsonl
from incident_analyzer.ingestion import ImportSession
from incident_analyzer.models import InputFile
from incident_analyzer.detection import analyze


def generate_records():
    # 1,000 independent hosts, each with 5 failures, success, task and 3 background successes.
    source = build_scenarios()["suspicious_sequence"][-7:]
    rows = []
    base = datetime(2026, 1, 15, 9, tzinfo=timezone.utc)
    for group in range(1000):
        for index in range(10):
            row = dict(source[index] if index < 7 else source[5])
            row["hostname"] = f"SYNTHETIC-{group:04d}"
            row["record_id"] = group * 10 + index + 1
            minute = [0, 1, 2, 3, 4, 5, 8, 30, 31, 32][index]
            row["timestamp"] = (base + timedelta(minutes=minute)).isoformat()
            rows.append(row)
    random.Random(56).shuffle(rows)
    return rows


def read_host_metadata(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def main():
    output = ROOT / "generated-artifacts/validation"
    output.mkdir(parents=True, exist_ok=True)
    content = render_jsonl(generate_records())
    (output / "benchmark_10000.synthetic.jsonl").write_bytes(content)
    measurements = []
    for iteration in range(3):
        session = ImportSession()
        start = perf_counter()
        session.import_files([InputFile("benchmark_10000.synthetic.jsonl", content)])
        imported = perf_counter()
        result = analyze(session)
        ended = perf_counter()
        counts = dict(Counter(f.rule_id for f in result.findings))
        assert len(session.events) == 10000 and counts == {"R1": 1000, "R2": 1000, "R3": 1000}
        measurements.append({"run": iteration + 1, "ingestion_seconds": imported - start,
                             "detection_seconds": ended - imported, "findings": counts})
    details = {
        "synthetic": True, "seed": 56, "event_count": 10000, "bytes": len(content),
        "sha256": sha256(content).hexdigest(), "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(), "platform": platform.platform(),
        "machine": platform.machine(), "logical_cpus_visible": os.cpu_count(),
        "versions": {name: version(name) for name in ("streamlit", "pandas", "pytest")},
        "cpu_model": next((line.split(":", 1)[1].strip()
                           for line in read_host_metadata("/proc/cpuinfo").splitlines()
                           if line.startswith("model name")), platform.processor() or "unknown"),
        "memory_visible": next((line for line in read_host_metadata("/proc/meminfo").splitlines()
                                if line.startswith("MemTotal")), "unavailable"),
        "cpu_quota": read_host_metadata("/sys/fs/cgroup/cpu.max") or "unavailable",
        "memory_limit": read_host_metadata("/sys/fs/cgroup/memory.max") or "unavailable",
        "measurement_scope": "perf_counter wall time, in-memory JSONL bytes, three fresh ImportSessions, generation/file I/O excluded; UI/export excluded",
        "runs": measurements,
    }
    (output / "benchmark-results.json").write_text(json.dumps(details, indent=2))
    print(json.dumps(details, indent=2))


if __name__ == "__main__":
    main()
