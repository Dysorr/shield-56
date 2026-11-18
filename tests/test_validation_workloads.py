from scripts.benchmark import generate_records
from scripts.generate_synthetic import render_jsonl
from scripts.validate_scenarios import run


def test_benchmark_is_reproducible_and_has_exact_event_count():
    first, second = generate_records(), generate_records()
    assert len(first) == 10000
    assert len({row["record_id"] for row in first}) == 10000
    assert render_jsonl(first) == render_jsonl(second)


def test_all_scenario_formats_and_repeated_imports():
    assert len(run()) == 6
