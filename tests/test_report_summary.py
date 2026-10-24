"""Reports for large orgs: summarized with top action items instead of refused."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import main  # noqa: E402


def _f(i, sev, fix, cat="Internet-facing service", host=None, status="OPEN"):
    return {"id": f"F-{i}", "title": f"Finding {i}", "severity": sev, "category": cat,
            "target": host or f"h{i}.example.com", "status": status, "remediation": [fix],
            "description": "d", "related_cves": []}


def _many(n):
    fs = [_f(0, "CRITICAL", "Close RDP to the internet."),
          _f(1, "HIGH", "Upgrade nginx to 1.25.4 or later.")]
    fs += [_f(i, "MEDIUM", "Limit exposure via firewall/ACL.", cat=("Database" if i % 2 else "Mail"))
           for i in range(2, n)]
    return fs


def test_action_items_group_by_fix_rank_by_severity_then_reach():
    fs = _many(40) + [_f(90, "LOW", "Suppress version tokens.", host="h2.example.com"),
                      _f(91, "HIGH", "Upgrade nginx to 1.27.0 or later."),   # same fix, other digits
                      _f(92, "CRITICAL", "Ignored.", status="RESOLVED"),
                      _f(93, "CRITICAL", "Ignored too.", status="ACCEPTED_RISK")]
    items, n = main._report_action_items(fs)
    assert n == 4
    assert [i["severity"] for i in items] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert items[1]["count"] == 2                      # 1.25.4 and 1.27.0 group together
    firewall = items[2]
    assert firewall["count"] == 38 and len(firewall["hosts"]) == 38
    assert set(firewall["categories"]) == {"Database", "Mail"}


def test_action_items_unwrap_ai_quoted_remediation():
    f = _f(1, "HIGH", None)
    f["remediation"] = '"Limit public access to 21/ftp via firewall/ACL."'
    items, _ = main._report_action_items([f])
    assert items[0]["fix"] == "Limit public access to 21/ftp via firewall/ACL."


def test_large_report_summarizes_and_details_only_critical_and_high():
    html = main._build_report_html("sample", {"name": "Big"}, _many(600), ["example.com"])
    assert "Top 10 action items" in html and "Most affected hosts" in html
    assert "Findings by category" in html
    assert "600 live findings: detailed below are the 2 critical and high ones" in html
    assert "<h2>1. Finding 0</h2>" in html and "<h2>2. Finding 1</h2>" in html
    assert "Finding 5</h2>" not in html
    assert len(html) < 200_000


def test_small_report_keeps_every_finding_in_severity_order():
    fs = [_f(1, "LOW", "a"), _f(2, "CRITICAL", "b"), _f(3, "MEDIUM", "c")]
    html = main._build_report_html("sample", {"name": "Small"}, fs, ["example.com"])
    assert "Top 10 action items" in html
    assert "live findings: detailed below" not in html
    assert html.index("1. Finding 2") < html.index("2. Finding 3") < html.index("3. Finding 1")


def test_summary_escapes_hosts_and_fixes():
    f = _f(1, "HIGH", "<script>alert(1)</script>", host="<img src=x>")
    html = main._report_summary_html([f], 1, 1)
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html


def test_oversized_report_falls_back_to_summary(monkeypatch):
    fs = _many(30)
    monkeypatch.setattr(main.cc, "load_data", lambda slug: (fs, ""))
    monkeypatch.setattr(main, "_require_org", lambda slug, req: (None, {"name": "Big"}))
    full = main._build_report_html("sample", {"name": "Big"}, fs, [])
    monkeypatch.setattr(main, "_MAX_PDF_HTML_SIZE", len(full) - 1)
    html, err = main._prepare_report("sample", None)
    assert err is None and "Top 10 action items" in html
    assert "<h2>1. Finding" not in html
