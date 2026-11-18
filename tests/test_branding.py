"""Contrast and static markup checks; not a complete accessibility audit."""

import re
import tomllib
from pathlib import Path

import pytest

from incident_analyzer.branding import CSS, FLAG_SVG, HEADER_HTML

ROOT = Path(__file__).resolve().parents[1]


def luminance(color):
    values = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in values
    ]
    return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))


def contrast(first, second):
    low, high = sorted((luminance(first), luminance(second)))
    return (high + 0.05) / (low + 0.05)


@pytest.mark.parametrize(
    "foreground,background,minimum",
    [
        ("#F8FAFC", "#0B1220", 4.5),
        ("#F8FAFC", "#152033", 4.5),
        ("#CBD5E1", "#0B1220", 4.5),
        ("#CBD5E1", "#152033", 4.5),
        ("#FFFFFF", "#008751", 4.5),
        ("#22C55E", "#152033", 3),
        ("#7DD3FC", "#152033", 3),
        ("#7DD3FC", "#0B1220", 3),
    ],
)
def test_brand_color_pair_contrast(foreground, background, minimum):
    assert contrast(foreground, background) >= minimum


def test_theme_uses_supported_identity_palette():
    theme = tomllib.loads((ROOT / ".streamlit/config.toml").read_text(encoding="utf-8"))["theme"]
    assert theme["base"] == "dark"
    assert theme["primaryColor"] == "#008751"
    assert theme["backgroundColor"] == "#0B1220"
    assert theme["secondaryBackgroundColor"] == "#152033"
    assert theme["textColor"] == "#F8FAFC"
    assert theme["font"] == "sans-serif"
    assert theme["codeFont"] == "monospace"


def test_header_flag_and_focus_are_labeled_and_static():
    assert '<h1 class="s56-name">' in HEADER_HTML
    assert 'alt="Flag of Jordan"' in HEADER_HTML
    assert "Security Incident Timeline Analyzer" in HEADER_HTML
    assert "Shield 56" in HEADER_HTML
    assert ":focus-visible" in CSS
    assert 'viewBox="0 0 840 420"' in FLAG_SVG
    assert "#FFFFFF" in FLAG_SVG


def test_relative_documentation_links_resolve():
    documents = [ROOT / "README.md", ROOT / "PROJECT_SPEC.md", *sorted((ROOT / "docs").glob("*.md"))]
    for document in documents:
        for destination in re.findall(r"\[[^]]+\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
            if "://" not in destination and not destination.startswith("#"):
                assert (document.parent / destination.split("#")[0]).exists(), destination
