"""Protect the public naming contract without claiming exports already exist."""

from incident_analyzer.identity import (
    DOWNLOAD_PREFIX, PRODUCT_NAME, REPORT_TITLE, SUBTITLE, SUGGESTED_REPOSITORY,
)


def test_public_identity_contract():
    assert PRODUCT_NAME == "Shield 56"
    assert SUBTITLE == "Security Incident Timeline Analyzer"
    assert SUGGESTED_REPOSITORY == "shield-56"
    assert REPORT_TITLE == "Shield 56 — Incident Investigation Report"
    assert DOWNLOAD_PREFIX == "shield56_"
