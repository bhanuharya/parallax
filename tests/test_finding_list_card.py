"""List-view projection carries enough for an informative collapsed card."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402


def _finding(**kw):
    f = {"id": "SRV-sample-1", "title": "Database exposure", "severity": "MEDIUM",
         "category": "Database", "status": "OPEN", "status_detail": "SCAN-DETECTED (TCP connect)",
         "target": "db.example.com", "ip": "203.0.113.7", "port": 5432,
         "found_date": "2026-10-24",
         "description": "Host db.example.com is reachable. Open ports: 5432/postgresql."}
    f.update(kw)
    return f


def test_light_projection_includes_port_and_summary():
    light = cc.normalize_finding_light(_finding(), "sample", meta_date="2026-10-24")
    assert light["port"] == 5432
    assert light["summary"] == "Host db.example.com is reachable. Open ports: 5432/postgresql."


def test_summary_is_capped_on_a_word_boundary():
    desc = "exposed service " * 40
    light = cc.normalize_finding_light(_finding(description=desc), "sample", meta_date="2026-10-24")
    s = light["summary"]
    assert len(s) <= cc._SUMMARY_MAX + 1 and s.endswith("…")
    assert not s[:-1].endswith(" ")
    assert "  " not in s


def test_summary_unwraps_ai_quoted_reason_and_masks_pii():
    desc = '"Admin panel open; contact ops@example.com for access"'
    light = cc.normalize_finding_light(_finding(description=desc), "sample", meta_date="2026-10-24")
    assert not light["summary"].startswith('"') and not light["summary"].endswith('"')
    assert "ops@example.com" not in light["summary"]


def test_summary_absent_without_description():
    light = cc.normalize_finding_light(_finding(description=""), "sample", meta_date="2026-10-24")
    assert light["summary"] is None
