"""Product contracts: actionable evidence, honest progress, portable reports."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import cti_correlation as cc
import main
import posture
import scanner
import scorecard as sc
from fastapi.testclient import TestClient
import pytest


def card(score_loss=False):
    return sc.scorecard_for_domain(
        "example.com", software_rows=[], software_assessed=True,
        cert_rows=[{"host": "www.example.com", "issues": ["expired"] if score_loss else []}],
        dns_result={"score": 100, "grade": "A", "issues": []},
        service_rows=[{"host": "www.example.com", "open": {}}],
        web_rows=[{"host": "www.example.com", "url": "https://www.example.com", "code": "200",
                   "strict-transport-security": "max-age=31536000",
                   "content-security-policy": "default-src 'self'",
                   "x-content-type-options": "nosniff", "assets": []}])


def snap(score_loss=False):
    return posture.snapshot([card(score_loss)], {"fingerprints": {"www.example.com": {}}})


def event(snapshot, at="2026-10-22T12:00:00"):
    return {"kind": "scan", "ts": at, "posture": snapshot}


def test_progress_preserves_zero_and_compares_previous_scan():
    old, current = snap(True), snap()
    result = posture.progress(current, [event(old), event(current)])
    assert result["changes"][0]["delta"] == card()["score"] - card(True)["score"] > 0
    result = posture.progress(current, [event(current), event(current)])
    assert result["changes"][0]["delta"] == 0


@pytest.mark.parametrize("change,reason", [
    ("scope", "Coverage changed"), ("coverage", "Coverage changed"),
    ("unknown", "Insufficient evidence"), ("version", "Scoring model changed")])
def test_progress_rejects_misleading_improvement(change, reason):
    old, current = snap(True), snap()
    if change == "version":
        old["version"] = 0
    else:
        old["domains"][0][change] = {"scope": "different", "coverage": 40, "unknown": True}[change]
    row = posture.progress(current, [event(old), event(current)])["changes"][0]
    assert not row["comparable"] and row["delta"] is None
    assert reason in row["reason"]


def test_history_has_no_fabricated_baseline_and_ignores_non_scan_events():
    result = posture.progress(snap(), [{"kind": "scan"}, {**event(snap(True)), "kind": "correlate"}])
    assert result["history"] == []
    assert result["changes"][0]["delta"] is None
    assert len(posture.progress(snap(), [event(snap()) for _ in range(12)])["history"]) == 8


def test_scope_detects_lost_host_and_dns_observations():
    meta = {"fingerprints": {"www.example.com": {}}, "dns_posture": [
        {"domain": "example.com", "checks": {"spf": {"unknown": False}}}]}
    old = posture.snapshot([card()], meta)
    meta["dns_posture"][0]["checks"]["spf"]["unknown"] = True
    assert old != posture.snapshot([card()], meta)
    meta["fingerprints"]["api.example.com"] = {}
    assert old != posture.snapshot([card()], meta)


def test_actions_keep_unknown_distinct_from_remediation():
    actions = posture.action_plan([sc.scorecard_for_domain("example.com")])
    assert len(actions) == len(sc.WEIGHTS)
    assert all(a["priority"] == "Assess" for a in actions)
    assert posture.action_plan([card()]) == []


def test_version_upgrade_is_comparable_but_lost_version_evidence_is_not():
    fp = {"versions": [{"product": "app", "version": "1.0"}]}
    meta = {"fingerprints": {"www.example.com": fp}}
    old = posture.snapshot([card()], meta)
    fp["versions"][0]["version"] = "2.0"
    assert old == posture.snapshot([card()], meta)
    fp["versions"] = []
    assert old != posture.snapshot([card()], meta)


def test_critical_match_survives_deduction_cap_and_leads_actions():
    rows = [{"host": f"h{i}.example.com", "product": "library", "version": "1",
             "cve_count": 10, "related_cves": ["CVE-HIGH"]} for i in range(10)]
    rows.append({"host": "critical.example.com", "product": "app", "version": "1",
                 "cve_count": 1, "related_cves": ["CVE-CRITICAL"]})
    c = sc.scorecard_for_domain("example.com", rows,
        [{"host": "www.example.com", "issues": []}], {"score": 100, "grade": "A"}, [],
        {"CVE-HIGH": "HIGH", "CVE-CRITICAL": "CRITICAL"})
    assert c["score"] <= 60 and c["critical_exposure"]
    assert sc.summarize([c])["with_critical"] == 1
    assert "critical.example.com" in posture.action_plan([c])[0]["title"]
    assert posture.action_plan([c])[0]["priority"] == "Urgent review"


def test_header_respects_low_coverage_grade():
    c = sc.scorecard_for_domain("example.com", software_assessed=True,
                                cert_rows=[{"host": "www.example.com", "issues": []}])
    assert c["coverage"] < 60
    assert c["grade"] == "D"
    assert sc.summarize([c])["average_grade"] == "D"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    fp, hp = tmp_path / "findings.json", tmp_path / "history.json"
    fp.write_text(json.dumps({"meta": {"date": "2026-10-22", "fingerprints": {
        "www.example.com": {"url": "https://www.example.com", "code": "200",
                            "assets": []}}}, "findings": []}))
    monkeypatch.setattr(cc, "REGISTRY", {"brief": {"name": "Demo", "domains": ["example.com"]}})
    monkeypatch.setattr(cc, "_org_paths", lambda slug: (str(fp), None))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    monkeypatch.setattr(cc, "history_path", lambda slug: str(hp))
    monkeypatch.setattr(scanner, "_history_path", lambda slug: str(hp))
    cc.invalidate_org_cache("brief")
    yield fp, hp
    cc.invalidate_org_cache("brief")


def test_scan_persists_history_and_reads_survive_cache_reset(workspace):
    fp, hp = workspace
    scanner.record_scan_event("brief", "fast", 1)
    first = json.loads(hp.read_text())
    assert first[0]["posture"]["domains"][0]["domain"] == "example.com"
    scanner.record_scan_event("brief", "fast", 1)
    cc.invalidate_org_cache("brief")
    result = cc.scorecard("brief")
    assert result["progress"]["changes"][0]["delta"] == 0
    before = hp.read_bytes()
    cc.scorecard("brief")
    assert hp.read_bytes() == before, "GET must not add history events"
    scanner.record_scan_event("brief", "correlate", 1)
    assert "posture" not in json.loads(hp.read_text())[-1]


def test_report_auth_tenant_isolation_and_html_fallback(workspace, monkeypatch):
    client = TestClient(main.app)
    auth = {"X-CTI-Token": "test-tok"}
    for suffix in ("html", "pdf"):
        assert client.get(f"/api/orgs/brief/report.{suffix}").status_code == 401
        assert client.get(f"/api/orgs/unknown/report.{suffix}", headers=auth).status_code == 404
    monkeypatch.setattr(main, "_CHROMIUM", None)
    for suffix in ("html", "pdf"):
        r = client.get(f"/api/orgs/brief/report.{suffix}", headers=auth)
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert 'brief-report.html' in r.headers["content-disposition"]
        assert "Executive security brief" in r.text and "Next actions" in r.text
        assert "Coverage" in r.text and "Assess certificate hygiene" in r.text


def test_report_escapes_and_masks_posture_evidence():
    data = {"summary": {}, "domains": [], "actions": [{
        "priority": "Remediate", "domain": "example.com", "title": '<script>alert(1)</script>',
        "next_step": "Contact admin@example.com"}]}
    output = main._report_posture_html(data)
    assert "<script>" not in output and "&lt;script&gt;" in output
    assert "admin@example.com" not in output


@pytest.mark.parametrize("body,expected", [
    ('Enjoy the horizon. Press F5, view client stories and have a blast.', set()),
    ('<form action="/my.policy">Sign in</form>', {"f5 big-ip"}),
    ('<title>VMware Horizon HTML Access</title>', {"vmware horizon"})])
def test_legacy_appliance_signatures_need_specific_evidence(body, expected):
    labels = {label for label, regex in scanner._TECH_SIGNATURES
              if label in ("f5 big-ip", "vmware horizon") and regex.search(body)}
    assert labels == expected
