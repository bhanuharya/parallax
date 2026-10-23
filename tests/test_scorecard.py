"""Per-domain security scorecard.

The properties these tests defend are the ones that make a rating trustworthy:

  - deterministic and itemized (every point traceable to a deduction);
  - unknown never reads as good (an unexamined pillar cannot score clean);
  - a critical CVE cannot be laundered by clean hygiene elsewhere;
  - partial coverage cannot earn a top grade;
  - a host is never counted against two domains.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scorecard as sc  # noqa: E402


# --------------------------------------------------------------------------
# helpers / grades
# --------------------------------------------------------------------------
def test_grade_bands():
    assert sc.grade_for(100) == "A"
    assert sc.grade_for(90) == "A"
    assert sc.grade_for(89) == "B"
    assert sc.grade_for(80) == "B"
    assert sc.grade_for(70) == "C"
    assert sc.grade_for(55) == "D"
    assert sc.grade_for(54) == "F"
    assert sc.grade_for(0) == "F"


def test_hosts_for_domain():
    assert sc.hosts_for_domain("example.com", "example.com")
    assert sc.hosts_for_domain("example.com", "www.example.com")
    assert sc.hosts_for_domain("example.com", "a.b.example.com")
    assert not sc.hosts_for_domain("example.com", "notexample.com")
    assert not sc.hosts_for_domain("example.com", "example.com.evil.tld")
    assert not sc.hosts_for_domain("", "example.com")


# --------------------------------------------------------------------------
# pillars
# --------------------------------------------------------------------------
def _sw(host="h.example.com", product="wordpress", version="4.7.1",
        cves=("CVE-2017-1001000",)):
    return {"host": host, "product": product, "version": version,
            "cve_count": len(cves), "related_cves": list(cves)}


SEV = {"CVE-2017-1001000": "CRITICAL", "CVE-2022-21661": "HIGH"}


def test_vulnerability_pillar_scores_critical_higher():
    crit = sc.vulnerability_pillar([_sw(cves=("CVE-2017-1001000",))], SEV)
    high = sc.vulnerability_pillar([_sw(cves=("CVE-2022-21661",))], SEV)
    assert crit["earned"] < high["earned"]


def test_vulnerability_pillar_capped():
    rows = [_sw(host="h%d.example.com" % i) for i in range(20)]
    v = sc.vulnerability_pillar(rows, SEV)
    assert v["score"] == 100 - sc._CVE_POINTS_MAX


def test_unknown_cve_severity_treated_as_medium_not_critical():
    v = sc.vulnerability_pillar([_sw(cves=("CVE-9999-00000",))], SEV)
    detail = v["deductions"][0]["detail"]
    assert "MEDIUM" in detail


def test_vulnerability_pillar_not_assessed_is_unknown():
    v = sc.vulnerability_pillar([], {}, assessed=False)
    assert v["unknown"] is True


def test_vulnerability_pillar_assessed_clean_scores_full():
    v = sc.vulnerability_pillar([], {}, assessed=True)
    assert v["unknown"] is False
    assert v["earned"] == sc.WEIGHTS["vulnerability"]


def test_certificate_pillar_deducts_per_issue():
    rows = [{"host": "h.example.com", "issues": ["expired", "untrusted chain"]}]
    v = sc.certificate_pillar(rows)
    codes = [d["code"] for d in v["deductions"]]
    assert "cert:h.example.com:expired" in codes
    assert v["earned"] < sc.WEIGHTS["certificates"]


def test_certificate_pillar_clean_cert_scores_full():
    v = sc.certificate_pillar([{"host": "h.example.com", "issues": []}])
    assert v["earned"] == sc.WEIGHTS["certificates"]
    assert v["deductions"] == []


def test_exposed_pillar_flags_high_risk_ports():
    v = sc.exposed_pillar([{"host": "h.example.com",
                            "open": {"443": "https", "3389": "rdp", "3306": "mysql"}}])
    labels = " ".join(d["label"] for d in v["deductions"])
    assert "RDP" in labels and "MySQL" in labels
    assert "https" not in labels.lower()


def test_exposed_pillar_https_only_is_clean():
    v = sc.exposed_pillar([{"host": "h.example.com", "open": {"443": "https"}}])
    assert v["deductions"] == []


def test_exposed_pillar_no_scan_is_unknown():
    assert sc.exposed_pillar(None)["unknown"] is True


def test_email_dns_pillar_reuses_posture_score():
    dns = {"domain": "example.com", "grade": "A", "score": 100, "issues": []}
    v = sc.email_dns_pillar(dns)
    assert v["earned"] == sc.WEIGHTS["email_dns"]
    bad = sc.email_dns_pillar({"domain": "example.com", "grade": "F", "score": 20,
                               "issues": [{"check": "dmarc", "severity": "MEDIUM",
                                           "message": "no DMARC"}]})
    assert bad["earned"] < v["earned"]
    assert any("dmarc" in d["code"] for d in bad["deductions"])


def test_email_dns_pillar_unknown_grade_is_unknown():
    assert sc.email_dns_pillar(None)["unknown"] is True
    assert sc.email_dns_pillar({"grade": "?"})["unknown"] is True


# --------------------------------------------------------------------------
# whole-card behaviour
# --------------------------------------------------------------------------
GOOD_CERT = [{"host": "h.example.com", "issues": []}]
GOOD_DNS = {"domain": "example.com", "grade": "A", "score": 100, "issues": []}
GOOD_SVC = [{"host": "h.example.com", "open": {"443": "https"}}]
# a host that was fingerprinted and disclosed only current software: the
# vulnerability pillar is genuinely ASSESSED and clean
GOOD_SW = [{"host": "h.example.com", "product": "nginx", "version": "1.27.0",
            "cve_count": 0, "related_cves": []}]
# a web response carrying every header the application and disclosure
# factors look for, so both are assessed and clean
GOOD_WEB = [{"host": "h.example.com", "url": "https://h.example.com", "code": "200",
             "server": "nginx", "strict-transport-security": "max-age=31536000",
             "content-security-policy": "default-src 'self'",
             "x-frame-options": "DENY", "x-content-type-options": "nosniff",
             "assets": []}]


def test_perfect_domain_scores_a():
    c = sc.scorecard_for_domain("example.com", GOOD_SW, GOOD_CERT, GOOD_DNS, GOOD_SVC,
                                web_rows=GOOD_WEB)
    assert c["score"] == 100
    assert c["grade"] == "A"
    assert c["coverage"] == 100
    assert c["confidence"] == "high"
    assert c["issues"] == []


def test_critical_cve_caps_grade_despite_clean_hygiene():
    c = sc.scorecard_for_domain(
        "example.com", [_sw(cves=("CVE-2017-1001000",))],
        GOOD_CERT, GOOD_DNS, GOOD_SVC, SEV)
    assert c["critical_cap"] is True
    assert c["score"] <= 60
    assert c["grade"] in ("C", "D", "F")


def test_never_examined_is_zero_and_unknown():
    c = sc.scorecard_for_domain("never.example.com")
    assert c["score"] == 0
    assert c["grade"] == "?"
    assert c["unknown"] is True
    assert c["coverage"] == 0


def test_missing_pillar_does_not_earn_clean_credit():
    """The central rule: a pillar with no data is excluded from the average,
    but the RESULTING grade is capped because the evidence is partial."""
    full = sc.scorecard_for_domain("e.com", GOOD_SW, GOOD_CERT, GOOD_DNS, GOOD_SVC,
                                   web_rows=GOOD_WEB)
    partial = sc.scorecard_for_domain("e.com", GOOD_SW, GOOD_CERT, GOOD_DNS, None,
                                      web_rows=GOOD_WEB)
    assert full["grade"] == "A"
    assert partial["coverage"] < 100
    assert partial["grade"] != "A"
    assert partial["coverage_cap"] is True


def test_unfingerprinted_domain_is_not_clean_vulnerability():
    looked = sc.scorecard_for_domain("e.com", GOOD_SW, GOOD_CERT, GOOD_DNS, GOOD_SVC,
                                     software_assessed=True, web_rows=GOOD_WEB)
    never = sc.scorecard_for_domain("e.com", [], GOOD_CERT, GOOD_DNS, GOOD_SVC,
                                    software_assessed=False, web_rows=GOOD_WEB)
    assert looked["coverage"] == 100 and looked["grade"] == "A"
    assert never["coverage"] < 100
    assert never["coverage_cap"] is True
    assert never["grade"] != "A"


def test_issues_sorted_by_gain():
    c = sc.scorecard_for_domain(
        "example.com",
        [_sw(cves=("CVE-2017-1001000",))],
        [{"host": "h.example.com", "issues": ["expiring soon"]}],
        GOOD_DNS, GOOD_SVC, SEV, web_rows=GOOD_WEB)
    gains = [i["gain"] for i in c["issues"]]
    assert gains == sorted(gains, reverse=True)
    assert c["issues"][0]["type"] == "vuln-critical"


def test_every_deduction_has_code_and_points():
    c = sc.scorecard_for_domain(
        "example.com",
        [_sw(cves=("CVE-2017-1001000",))],
        [{"host": "h.example.com", "issues": ["expired"]}],
        {"domain": "example.com", "grade": "F", "score": 10,
         "issues": [{"check": "spf", "severity": "MEDIUM", "message": "missing"}]},
        [{"host": "h.example.com", "open": {"3389": "rdp"}}], SEV)
    for p in c["pillars"]:
        for d in p["deductions"]:
            assert d["code"] and isinstance(d["points"], int) and d["label"]


# --------------------------------------------------------------------------
# org build / attribution
# --------------------------------------------------------------------------
def test_build_one_card_per_registered_domain():
    meta = {"fingerprints": {"a.example.com": {}, "b.other.com": {}},
            "services": {}}
    cards = sc.build(["example.com", "other.com"], meta)
    assert [c["domain"] for c in cards] == ["example.com", "other.com"]


def test_build_does_not_double_count_overlapping_domains():
    """A host must be attributed to exactly one registered domain, otherwise
    its CVEs would count twice and both cards would look worse than reality."""
    sw = [{"host": "www.example.com", "product": "wordpress", "version": "4.7.1",
           "cve_count": 1, "related_cves": ["CVE-2017-1001000"]}]
    # a service scan as well, so the cards clear the 30% coverage floor
    meta = {"fingerprints": {"www.example.com": {}},
            "services": {"www.example.com": {"open": {"443": "https"}}}}
    cards = sc.build(["example.com", "www.example.com"], meta,
                     software_rows=sw, severity_map=SEV)
    scored = [c for c in cards if c["issues"]]
    assert len(scored) == 1
    total = sum(i["points"] for c in cards for i in c["issues"])
    once = sum(i["points"] for i in sc.scorecard_for_domain(
        "example.com", sw, [], None,
        [{"host": "www.example.com", "open": {"443": "https"}}], SEV)["issues"])
    assert once > 0
    assert total == once


def test_build_attributes_by_subdomain():
    sw = [{"host": "api.example.com", "product": "django", "version": "3.2.4",
           "cve_count": 1, "related_cves": ["CVE-2022-28346"]}]
    meta = {"services": {"api.example.com": {"open": {}}}}
    sev = {"CVE-2022-28346": "HIGH"}
    cards = {c["domain"]: c for c in
             sc.build(["example.com", "other.com"], meta,
                      software_rows=sw, severity_map=sev)}
    assert cards["example.com"]["issues"]
    assert not cards["other.com"]["issues"]


def test_summarize_rollup():
    good = sc.scorecard_for_domain("a.com", GOOD_SW, GOOD_CERT, GOOD_DNS, GOOD_SVC,
                                   web_rows=GOOD_WEB)
    bad = sc.scorecard_for_domain(
        "b.com", [_sw(host="h.b.com", cves=("CVE-2017-1001000",))],
        [{"host": "h.b.com", "issues": ["expired"]}], GOOD_DNS, GOOD_SVC, SEV)
    s = sc.summarize([good, bad])
    assert s["domains"] == 2 and s["assessed"] == 2
    assert s["worst_score"] <= s["average_score"] <= 100
    assert s["grades"].get("A") == 1


def test_summarize_handles_unknown_domains():
    s = sc.summarize([sc.scorecard_for_domain("x.com")])
    assert s["unknown"] == 1
    assert s["assessed"] == 0
    assert s["average_grade"] == "?"


def test_header_grade_never_exceeds_card_grade():
    """A card capped to C for partial coverage must not average back up into a
    B in the header — the top line cannot contradict the cards beneath it."""
    partial = sc.scorecard_for_domain("e.com", GOOD_SW, GOOD_CERT, GOOD_DNS, None,
                                      web_rows=GOOD_WEB)
    assert partial["score"] == 100
    assert partial["grade"] == "C" and partial["coverage_cap"] is True
    s = sc.summarize([partial])
    assert s["average_score"] == 100
    assert s["average_grade"] == "C"


def test_header_grade_reflects_critical_cap():
    crit = sc.scorecard_for_domain(
        "e.com", [_sw(cves=("CVE-2017-1001000",))], GOOD_CERT, GOOD_DNS, GOOD_SVC, SEV)
    s = sc.summarize([crit])
    assert s["with_critical"] == 1
    assert s["average_grade"] != "A"


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
def _client():
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


def test_scorecard_endpoint_requires_auth():
    r = _client().get("/api/scorecard", params={"org": "sample"})
    assert r.status_code in (401, 403)


def test_scorecard_endpoint_shape():
    """Shape check against whatever org the registry currently holds.

    Other modules reload the shared registry against their own data root, so
    this test must not assume the session registry still contains "sample" —
    it resolves the first registered org instead (and is skipped if a prior
    test left the registry empty).
    """
    import cti_correlation as cc
    orgs = list(cc.REGISTRY.keys())
    if not orgs:
        pytest.skip("registry empty after earlier tests")
    org = orgs[0]
    r = _client().get("/api/scorecard", params={"org": org},
                      headers={"X-CTI-Token": "test-tok"})
    assert r.status_code == 200
    body = r.json()
    assert set(body) >= {"summary", "domains", "scanned"}
    assert isinstance(body["domains"], list)
    assert set(body["summary"]) >= {"domains", "assessed", "average_score",
                                    "average_grade", "grades"}


def test_scorecard_endpoint_unknown_org_404():
    r = _client().get("/api/scorecard", params={"org": "no-such-org"},
                      headers={"X-CTI-Token": "test-tok"})
    assert r.status_code == 404


def test_scorecard_endpoint_unknown_org_404():
    r = _client().get("/api/scorecard", params={"org": "no-such-org"},
                      headers={"X-CTI-Token": "test-tok"})
    assert r.status_code == 404
