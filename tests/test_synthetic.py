"""Reproducibility, paired formats, and independently asserted scenario content."""

import ast
import csv
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
from xml.etree import ElementTree

import pytest

from incident_analyzer.schema import (
    EVENT_FIELDS, EventValidationError, SecurityEvent, decode_csv_record,
)
from scripts.generate_synthetic import generate
from scripts.synthetic_scenarios import build_scenarios

ROOT = Path(__file__).resolve().parents[1]
ANSWER_KEY = ROOT / "evaluation/scenario_answer_key.json"


def directory_bytes(directory):
    return {file.name: file.read_bytes() for file in directory.iterdir() if file.is_file()}


def test_generator_is_byte_reproducible_and_does_not_change_global_rng(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    random.seed(123)
    state = random.getstate()
    generate(first)
    assert random.getstate() == state
    generate(second)
    assert directory_bytes(first) == directory_bytes(second)
    generate(first)  # Re-running into an existing output also has identical bytes.
    assert directory_bytes(first) == directory_bytes(second)


def test_seed_changes_background_not_prescribed_sequence():
    first, second = build_scenarios(56), build_scenarios(57)
    assert first["normal_activity"] != second["normal_activity"]
    assert first["suspicious_sequence"][-7:] == second["suspicious_sequence"][-7:]
    assert first["edge_cases"] == second["edge_cases"]


def test_committed_fixtures_match_fresh_generation(tmp_path):
    generate(tmp_path)
    for name, content in directory_bytes(tmp_path).items():
        assert (ROOT / "data/synthetic" / name).read_bytes() == content, name


@pytest.mark.parametrize("scenario", ["normal_activity", "suspicious_sequence", "edge_cases"])
def test_csv_jsonl_and_memory_have_same_values_and_order(tmp_path, scenario):
    manifest = generate(tmp_path)
    dataset = manifest["datasets"][scenario]
    csv_path = tmp_path / dataset["files"]["csv"]["filename"]
    jsonl_path = tmp_path / dataset["files"]["jsonl"]["filename"]
    with csv_path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        assert tuple(reader.fieldnames) == EVENT_FIELDS
        csv_records = [decode_csv_record(row) for row in reader]
    jsonl_records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
    assert csv_records == jsonl_records == build_scenarios()[scenario]
    assert dataset["synthetic"] is manifest["synthetic"] is True
    assert manifest["seed"] == 56
    assert manifest["scenario_date"] == "2026-01-15"
    assert dataset["record_count"] == len(csv_records)
    for metadata in dataset["files"].values():
        file_path = tmp_path / metadata["filename"]
        assert ".synthetic." in file_path.name
        assert hashlib.sha256(file_path.read_bytes()).hexdigest() == metadata["sha256"]


@pytest.mark.parametrize("scenario", ["normal_activity", "suspicious_sequence"])
def test_valid_scenarios_all_pass_schema(scenario):
    records = build_scenarios()[scenario]
    for record in records:
        assert SecurityEvent.from_mapping(record).timestamp_utc.utcoffset().total_seconds() == 0
    assert len({record["record_id"] for record in records}) == len(records)


def test_normal_activity_is_below_threshold_and_has_admin_task():
    records = build_scenarios()["normal_activity"]
    failures = [record for record in records if record["event_id"] == 4625]
    assert len(failures) == 2 < 5
    assert len([row for row in records if row["event_id"] == 4624]) == 12
    task, = [record for record in records if record["event_id"] == 4698]
    assert task["subject_user"] == "lab_admin"
    assert task["subject_domain"] == "LAB"
    assert task["target_user"] is None
    assert task["source_ip"] is None


def test_exact_suspicious_sequence_and_correlation_roles():
    records = build_scenarios()["suspicious_sequence"]
    sequence = [row for row in records if row["record_id"] >= 2101]
    assert [row["record_id"] for row in sequence] == list(range(2101, 2108))
    assert [row["timestamp"] for row in sequence] == [
        f"2026-01-15T09:{minute:02d}:00Z" for minute in (0, 1, 2, 3, 4, 5, 8)
    ]
    assert [row["event_id"] for row in sequence] == [4625] * 5 + [4624, 4698]
    for row in sequence[:6]:
        assert (row["target_domain"], row["target_user"], row["hostname"],
                row["source_ip"], row["logon_type"]) == (
                    "LAB", "alice", "LAB-PC01", "192.0.2.10", 3,
                )
        assert row["subject_user"] is None
    success, task = sequence[-2:]
    assert task["hostname"] == success["hostname"]
    assert (task["subject_domain"], task["subject_user"]) == ("LAB", "alice")
    assert task["target_user"] is None
    assert task["subject_logon_id"] == success["target_logon_id"] == "0x1234"
    assert len(records) == 19  # Includes twelve normal background sign-ins.
    task_xml = ElementTree.fromstring(task["task_content"])
    assert task_xml.findtext(".//Command") == "cmd.exe"
    assert task_xml.findtext(".//Arguments") == (
        '/c echo SHIELD56_SYNTHETIC_MARKER> "%TEMP%\\shield56_synthetic_marker.txt"'
    )


def test_edge_cases_are_deliberate_and_accounted_for():
    records = build_scenarios()["edge_cases"]
    assert records[0] == records[2]
    assert records[0] is not records[2]
    assert records[0]["timestamp"] > records[1]["timestamp"]
    accepted, rejected = [], []
    for row in records:
        try:
            accepted.append(SecurityEvent.from_mapping(row))
        except EventValidationError:
            rejected.append(row["record_id"])
    assert rejected == [3003, 3004]
    assert len(accepted) == 8
    assert len({row.source_identity for row in accepted}) == 7
    by_id = {row.record_id: row for row in accepted}
    assert by_id[3005].source_ip is None
    assert by_id[3006].timestamp != by_id[3007].timestamp
    assert by_id[3006].timestamp_utc == by_id[3007].timestamp_utc
    assert by_id[3008].event_id == 65000
    assert "<script>" in by_id[3009].task_name


def test_answer_key_references_real_support_and_expected_windows():
    key = json.loads(ANSWER_KEY.read_text(encoding="utf-8"))
    scenarios = build_scenarios()
    for name, expected in key["scenarios"].items():
        rows = scenarios[name]
        assert len(rows) == expected["input_count"]
        by_id = {row["record_id"]: row for row in rows}
        for finding in expected["expected_findings"]:
            ids = finding["supporting_record_ids"]
            assert all(record_id in by_id for record_id in ids)
            assert len(ids) == len(set(ids))
    findings = key["scenarios"]["suspicious_sequence"]["expected_findings"]
    assert [row["supporting_record_ids"] for row in findings] == [
        [2101, 2102, 2103, 2104, 2105],
        [2101, 2102, 2103, 2104, 2105, 2106],
        [2101, 2102, 2103, 2104, 2105, 2106, 2107],
    ]
    assert key["scenarios"]["normal_activity"]["expected_findings"] == []
    assert key["scenarios"]["edge_cases"]["expected_findings"] == []
    assert len(findings) == 3


def test_runtime_and_generator_do_not_reference_evaluation_key():
    # Architectural guard: only tests/evaluation may consult the oracle.
    paths = [ROOT / "app.py", *sorted((ROOT / "incident_analyzer").glob("*.py")),
             ROOT / "scripts/generate_synthetic.py", ROOT / "scripts/synthetic_scenarios.py"]
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "scenario_answer_key" not in node.value
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(("evaluation", "tests"))
            if isinstance(node, ast.Import):
                assert not any(alias.name.startswith(("evaluation", "tests")) for alias in node.names)


def test_cli_runs_from_another_directory(tmp_path):
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_synthetic.py"), "--output-dir",
         str(tmp_path / "output")],
        cwd=tmp_path, capture_output=True, text=True, check=True,
    )
    assert "SYNTHETIC suspicious_sequence: 19 records" in result.stdout
    assert len(list((tmp_path / "output").iterdir())) == 7
