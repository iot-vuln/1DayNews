"""Smoke tests for the score() classifier in src/vuln_monitor.py.

Run from the repo root:
    python -m pytest test.py -q
"""
from src.vuln_monitor import score


def test_exclude_takes_priority():
    hit, reason, vuln_type = score("Reflected XSS in Example App")
    assert hit is False
    assert reason == "excluded"
    assert vuln_type is None


def test_rce_with_asset_and_cve():
    hit, reason, vuln_type = score(
        "Fortinet FortiOS remote code execution CVE-2026-1340"
    )
    assert hit is True
    assert vuln_type == "RCE"
    assert reason == "RCE+asset+CVE"


def test_no_hit_on_plain_text():
    hit, reason, vuln_type = score("Just a random newsletter about gardening")
    assert hit is False
    assert reason == "no hit"
    assert vuln_type is None
