from pathlib import Path
import struct

from scripts.create_public_source_export import included_files

ROOT = Path(__file__).resolve().parents[1]


def test_publication_bundle_has_checked_synthetic_reports_and_real_screenshots():
    markdown = ROOT / "docs/sample-reports/synthetic-suspicious-investigation.md"
    html = ROOT / "docs/sample-reports/synthetic-suspicious-investigation.html"
    md_text, html_text = markdown.read_text(encoding="utf-8"), html.read_text(encoding="utf-8")
    for text in (md_text, html_text):
        assert "SYNTHETIC DATA" in text
        assert "19" in text and "2101" in text and "LAB-PC01" in text
        assert "R1" in text and "R2" in text and "R3" in text
        assert "Proposed" in text
    assert "default-src 'none'" in html_text
    assert "<script" not in html_text.lower()

    images = ROOT / "docs/images"
    for name in ("synthetic-timeline.jpg", "synthetic-findings-evidence.jpg"):
        data = (images / name).read_bytes()
        assert data[:3] == b"\xff\xd8\xff"
        assert len(data) > 20_000
    png = (images / "synthetic-investigation-report.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", png[16:24]) == (1600, 1600)


def test_clean_export_manifest_excludes_workspace_private_paths():
    names = included_files()
    assert "app.py" in names and "uv.lock" in names and "requirements.txt" in names
    assert ".streamlit/config.toml" in names
    assert ".github/workflows/tests.yml" in names
    assert "data/synthetic/suspicious_sequence.synthetic.csv" in names
    assert "docs/sample-reports/synthetic-suspicious-investigation.html" in names
    assert "docs/images/synthetic-timeline.jpg" in names
    assert all(not name.startswith((".agents/", ".local/", "attached_assets/", ".git/")) for name in names)
    assert all(not name.startswith("artifacts/") for name in names)
    assert all(not name.startswith("generated-artifacts/") for name in names)
    assert all(not name.lower().endswith((".evtx", ".pcap", ".pcapng", ".log")) for name in names)


def test_public_export_only_includes_streamlit_theme(tmp_path, monkeypatch):
    from scripts import create_public_source_export

    monkeypatch.setattr(create_public_source_export, "ROOT", tmp_path)
    streamlit = tmp_path / ".streamlit"
    streamlit.mkdir()
    (streamlit / "config.toml").touch()
    (streamlit / "secrets.toml").touch()

    assert included_files() == [".streamlit/config.toml"]
