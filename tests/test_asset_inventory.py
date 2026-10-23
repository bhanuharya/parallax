"""Asset inventory: certificate and software/version inventory.

Covers the inventory layer added on top of the passive scan:

- certificate hostname matching (RFC 6125 exact / wildcard / IP SAN)
- certificate issues beyond expired/self-signed (expiring soon, name
  mismatch, untrusted chain) and their severity mapping
- the full inventory payload (healthy certs included, worst-first ordering)
- software inventory rows joined with matched CVEs
- the authenticated API endpoints
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402
import scanner  # noqa: E402


# --------------------------------------------------------------------------
# hostname matching
# --------------------------------------------------------------------------
def test_hostname_exact_match():
    sans = [("DNS", "app.example.com")]
    assert scanner._hostname_matches_cert("app.example.com", sans, "app.example.com")
    assert not scanner._hostname_matches_cert("other.example.com", sans, "app.example.com")


def test_hostname_wildcard_matches_one_label_only():
    sans = [("DNS", "*.example.com")]
    assert scanner._hostname_matches_cert("a.example.com", sans, "")
    # a wildcard covers exactly one label, not a deeper name
    assert not scanner._hostname_matches_cert("a.b.example.com", sans, "")


def test_hostname_case_and_trailing_dot_normalized():
    sans = [("DNS", "App.Example.COM")]
    assert scanner._hostname_matches_cert("app.example.com.", sans, "")


def test_hostname_ip_san():
    sans = [("IP Address", "198.51.100.7")]
    assert scanner._hostname_matches_cert("198.51.100.7", sans, "")
    assert not scanner._hostname_matches_cert("198.51.100.8", sans, "")


def test_hostname_cn_fallback_only_without_sans():
    assert scanner._hostname_matches_cert("a.example.com", [], "a.example.com")
    # when SANs exist they are authoritative; a CN mismatch is not rescued
    sans = [("DNS", "other.example.com")]
    assert not scanner._hostname_matches_cert("a.example.com", sans, "a.example.com")


def test_hostname_mismatch_detected():
    sans = [("DNS", "wrong.example.com")]
    assert not scanner._hostname_matches_cert("app.example.com", sans, "wrong.example.com")


# --------------------------------------------------------------------------
# certificate findings
# --------------------------------------------------------------------------
@pytest.fixture
def org_home(tmp_path, monkeypatch):
    """Isolated org whose findings file starts empty."""
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))
    return org_dir


def test_expiring_soon_produces_finding(org_home):
    certs = {"a.example.com": {"port": 443, "days_left": 9, "expired": False,
                               "expiring_soon": True, "self_signed": False,
                               "hostname_ok": True, "chain_trusted": True,
                               "issuer_cn": "R3"}}
    out = scanner.synthesize_cert_findings("sample", certs)
    assert len(out) == 1
    assert "expiring soon" in out[0]["title"].lower()
    assert out[0]["severity"] == "LOW"
    assert "9 day(s)" in out[0]["description"]


def test_hostname_mismatch_produces_medium_finding(org_home):
    certs = {"a.example.com": {"port": 443, "days_left": 200, "expired": False,
                               "expiring_soon": False, "self_signed": False,
                               "hostname_ok": False, "chain_trusted": True,
                               "issuer_cn": "R3", "san_count": 1,
                               "sans": ["wrong.example.com"]}}
    out = scanner.synthesize_cert_findings("sample", certs)
    assert len(out) == 1
    assert "hostname mismatch" in out[0]["title"].lower()
    assert out[0]["severity"] == "MEDIUM"


def test_untrusted_chain_produces_finding(org_home):
    certs = {"a.example.com": {"port": 443, "days_left": 200, "expired": False,
                               "self_signed": False, "hostname_ok": True,
                               "chain_trusted": False,
                               "chain_error": "unable to get local issuer certificate",
                               "issuer_cn": "Intermediate CA"}}
    out = scanner.synthesize_cert_findings("sample", certs)
    assert len(out) == 1
    assert "untrusted chain" in out[0]["title"].lower()
    assert "unable to get local issuer" in out[0]["description"]


def test_healthy_cert_produces_no_finding(org_home):
    certs = {"a.example.com": {"port": 443, "days_left": 250, "expired": False,
                               "expiring_soon": False, "self_signed": False,
                               "hostname_ok": True, "chain_trusted": True,
                               "issuer_cn": "R3"}}
    assert scanner.synthesize_cert_findings("sample", certs) == []


def test_cert_findings_capped(org_home, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_CERT_FINDINGS", 2)
    certs = {"h%d.example.com" % i: {"port": 443, "expired": True, "days_left": -1,
                                     "self_signed": False, "hostname_ok": True,
                                     "chain_trusted": True}
             for i in range(5)}
    out = scanner.synthesize_cert_findings("sample", certs)
    assert len(out) == 2


# --------------------------------------------------------------------------
# certificate inventory payload
# --------------------------------------------------------------------------
def test_certificate_inventory_includes_healthy_and_sorts_worst_first():
    meta = {"certificates": {
        "healthy.example.com": {"port": 443, "days_left": 250, "expired": False,
                                "expiring_soon": False, "self_signed": False,
                                "hostname_ok": True, "chain_trusted": True,
                                "issuer_cn": "R3", "issuer_org": "Let's Encrypt",
                                "not_after": "Nov 1 00:00:00 2026 GMT", "san_count": 2},
        "expired.example.com": {"port": 443, "days_left": -5, "expired": True,
                                "self_signed": False, "hostname_ok": True,
                                "chain_trusted": False, "issuer_cn": "R3",
                                "not_after": "Aug 1 00:00:00 2026 GMT"},
        "soon.example.com": {"port": 443, "days_left": 7, "expired": False,
                             "expiring_soon": True, "self_signed": False,
                             "hostname_ok": True, "chain_trusted": True,
                             "issuer_cn": "R3", "not_after": "Nov 1 00:00:00 2026 GMT"},
    }}
    rows = cc.certificates_from_meta(meta)
    hosts = [r["host"] for r in rows]
    assert hosts[0] == "expired.example.com"
    assert hosts[1] == "soon.example.com"
    assert "healthy.example.com" in hosts
    assert len(rows) == 3  # healthy certs are inventory, not findings

    summary = cc.certificate_summary(rows)
    assert summary["total"] == 3
    assert summary["ok"] == 1
    assert summary["expired"] == 1
    assert summary["expiring_soon"] == 1


def test_certificate_inventory_handles_missing_meta():
    assert cc.certificates_from_meta({}) == []
    assert cc.certificates_from_meta(None) == []
    assert cc.certificates_from_meta({"certificates": "not-a-dict"}) == []


# --------------------------------------------------------------------------
# software inventory
# --------------------------------------------------------------------------
def test_software_inventory_joins_cves():
    meta = {"fingerprints": {
        "app.example.com": {"url": "https://app.example.com", "server": "nginx/1.20.1",
                            "versions": [{"product": "nginx", "version": "1.20.1"}]},
        "api.example.com": {"url": "https://api.example.com",
                            "versions": [{"product": "Apache", "version": "2.4.49"}]},
    }}
    findings = [
        {"id": "CVM-1", "source": "scan-cve", "target": "app.example.com",
         "related_cves": ["CVE-2021-23017"]},
    ]
    rows = cc.software_from_meta(meta, findings)
    by_host = {r["host"]: r for r in rows}
    # nginx 1.20.1 is fixed. An older finding cannot override its current version.
    assert by_host["app.example.com"]["cve_count"] == 0
    assert by_host["app.example.com"]["finding_id"] == "CVM-1"
    # api: Apache 2.4.49 is genuinely vulnerable, resolved straight from the
    # CVE map even though no scan-cve finding exists for it
    assert by_host["api.example.com"]["cve_count"] == 2
    assert "CVE-2021-41773" in by_host["api.example.com"]["related_cves"]

    summary = cc.software_summary(rows)
    assert summary["total"] == 2
    assert summary["hosts"] == 2
    assert summary["vulnerable"] == 1


def test_software_inventory_lists_multiple_products_per_host():
    meta = {"fingerprints": {"h.example.com": {"versions": [
        {"product": "nginx", "version": "1.18.0"},
        {"product": "PHP", "version": "8.1.2"},
    ]}}}
    rows = cc.software_from_meta(meta, [])
    assert len(rows) == 2
    assert {r["product"] for r in rows} == {"nginx", "PHP"}


def test_software_inventory_empty_without_fingerprints():
    assert cc.software_from_meta({}, []) == []
    assert cc.software_from_meta({"fingerprints": {}}, []) == []


def test_software_inventory_matches_cves_without_findings():
    """The inventory must be self-sufficient: a vulnerable version is flagged
    even when no scan-cve finding was ever synthesized for it."""
    meta = {"fingerprints": {"h.example.com": {"versions": [
        {"product": "nginx", "version": "1.18.0"}]}}}
    rows = cc.software_from_meta(meta, [])
    assert rows[0]["cve_count"] == 1
    assert "CVE-2021-23017" in rows[0]["related_cves"]


def test_software_inventory_fixed_version_has_no_cves():
    meta = {"fingerprints": {"h.example.com": {"versions": [
        {"product": "nginx", "version": "1.20.1"}]}}}
    rows = cc.software_from_meta(meta, [])
    assert rows[0]["cve_count"] == 0
    assert rows[0]["related_cves"] == []



# --------------------------------------------------------------------------
# API surface
# --------------------------------------------------------------------------
def _client():
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


def _auth_headers():
    return {"X-CTI-Token": "test-tok"}


def test_certificates_endpoint_requires_auth():
    c = _client()
    r = c.get("/api/certificates", params={"org": "sample"})
    assert r.status_code in (401, 403)


def test_software_endpoint_requires_auth():
    c = _client()
    r = c.get("/api/software", params={"org": "sample"})
    assert r.status_code in (401, 403)


def test_certificates_endpoint_shape():
    c = _client()
    r = c.get("/api/certificates", params={"org": "sample"}, headers=_auth_headers())
    assert r.status_code == 200
    body = r.json()
    assert set(body) >= {"summary", "certificates", "scanned"}
    assert isinstance(body["certificates"], list)


def test_software_endpoint_shape():
    c = _client()
    r = c.get("/api/software", params={"org": "sample"}, headers=_auth_headers())
    assert r.status_code == 200
    body = r.json()
    assert set(body) >= {"summary", "software", "scanned"}
    assert isinstance(body["software"], list)


def test_certificates_endpoint_rejects_unknown_org():
    c = _client()
    r = c.get("/api/certificates", params={"org": "no-such-org"},
              headers=_auth_headers())
    assert r.status_code == 404


# --------------------------------------------------------------------------
# expanded CVE map coverage
# --------------------------------------------------------------------------
import cve_match  # noqa: E402


@pytest.mark.parametrize("product,version,cve", [
    ("Big-IP", "16.1.0", "CVE-2022-1388"),
    ("F5 BIG-IP", "15.1.0", "CVE-2023-46747"),
    ("Citrix NetScaler", "13.1.40", "CVE-2023-3519"),
    ("NetScaler ADC", "12.1.50", "CVE-2019-19781"),
    ("MOVEit Transfer", "2022.1.5", "CVE-2023-34362"),
    ("Jira Software", "8.2.0", "CVE-2019-11581"),
    ("Microsoft Exchange", "15.1.2000", "CVE-2021-34473"),
    ("OpenSSL", "3.0.6", "CVE-2022-3602"),
])
def test_expanded_cve_map_matches_vulnerable(product, version, cve):
    hits = cve_match.match_cves([{"product": product, "version": version}])
    assert cve in [h["cve"] for h in hits], (product, version, hits)


@pytest.mark.parametrize("product,version", [
    ("Big-IP", "17.1.1"),
    ("Citrix", "13.1.49"),
    ("MOVEit", "2023.0.1"),
    ("Jira", "8.4.0"),
    ("OpenSSL", "3.0.8"),
])
def test_expanded_cve_map_clears_fixed_versions(product, version):
    hits = cve_match.match_cves([{"product": product, "version": version}])
    assert hits == [], (product, version, hits)


def test_cve_map_entries_are_wellformed():
    """Every entry has a valid CVE id, recognized severity and ranges."""
    import re
    products = cve_match.load_map()
    for key, entry in products.items():
        for cve in entry.get("cves", []):
            assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve["cve"]), cve
            assert cve["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), cve
            assert cve.get("ranges"), cve
            assert cve.get("summary"), cve

