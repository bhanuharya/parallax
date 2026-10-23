"""Host (subdomain) ratings and the two false positives found on real data.

What these tests defend:

  - a client-side advisory withdrawn from the map (CVE-2023-38408, ssh-agent)
    never matches a server banner, and old findings cannot bring it back;
  - a host whose TLS certificate was captured is not "served without HTTPS"
    just because the fingerprint fetch refused its certificate;
  - the fingerprint fetch observes pages behind invalid certificates;
  - every observed host gets its own score from the same model, inheriting
    its domain's email/DNS posture but never a sibling's takeover;
  - the assistant can answer host-level questions and labels its citations.
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import assistant  # noqa: E402
import cti_correlation as cc  # noqa: E402
import cve_match  # noqa: E402
import dns_posture  # noqa: E402
import scanner  # noqa: E402
import scorecard as sc  # noqa: E402


# --------------------------------------------------------------------------
# withdrawn advisory
# --------------------------------------------------------------------------
def test_ssh_agent_cve_is_withdrawn_from_server_matching():
    assert "CVE-2023-38408" in cve_match.withdrawn_ids()
    for banner in ("7.4", "8.0", "9.3"):
        ids = {m["cve"] for m in cve_match.match_cves([{"product": "openssh", "version": banner}])}
        assert "CVE-2023-38408" not in ids, banner


def test_old_findings_cannot_resurrect_a_withdrawn_cve():
    meta = {"fingerprints": {"ssh.example.com": {"versions": [{"product": "openssh", "version": "7.4"}]}}}
    old = [{"id": "F1", "source": "scan-cve", "target": "ssh.example.com",
            "related_cves": ["CVE-2023-38408"]}]
    rows = cc.software_from_meta(meta, old)
    assert rows[0]["related_cves"] == [] and rows[0]["cve_count"] == 0


def test_withdrawn_entries_document_a_reason():
    data = json.load(open(os.path.join(os.path.dirname(cve_match.__file__), "cve_data.json")))
    for w in data["withdrawn"]:
        assert w["reason"] and w["source"].startswith("https://")
        assert all(c["cve"] != w["cve"] for e in data["products"].values() for c in e["cves"])


# --------------------------------------------------------------------------
# HTTPS with a refused certificate
# --------------------------------------------------------------------------
HTTP_ROW = {"host": "h.example.com", "url": "http://h.example.com", "code": "200", "assets": []}


def test_captured_certificate_means_https_is_served():
    flagged = sc.application_pillar([dict(HTTP_ROW)])
    assert "no-https" in {d["type"] for d in flagged["deductions"]}
    seen = sc.application_pillar([dict(HTTP_ROW, tls_seen=True)])
    assert "no-https" not in {d["type"] for d in seen["deductions"]}


def test_build_marks_hosts_with_certificates():
    meta = {"fingerprints": {"h.example.com": dict(HTTP_ROW)},
            "certificates": {"h.example.com": {"days_left": -5, "expired": True}}}
    card = sc.build(["example.com"], meta, cert_rows=cc.certificates_from_meta(meta))[0]
    app = next(p for p in card["pillars"] if p["pillar"] == "application")
    certs = next(p for p in card["pillars"] if p["pillar"] == "certificates")
    assert "no-https" not in {d["type"] for d in app["deductions"]}
    assert "cert-expired" in {d["type"] for d in certs["deductions"]}


def test_fingerprint_fetch_observes_pages_behind_invalid_certificates(monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="HTTP/2 200 \nserver: nginx\n\n<html></html>", stderr="")
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    _, snippet = scanner._fetch_fingerprint("expired.example.com")
    assert "--insecure" in seen[0] and seen[0][-1] == "https://expired.example.com/"
    assert snippet["url"] == "https://expired.example.com"


# --------------------------------------------------------------------------
# host ratings
# --------------------------------------------------------------------------
GOOD = {"url": "https://{h}", "code": "200", "server": "nginx",
        "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff", "assets": []}


def _fp(host, **over):
    row = {k: (v.format(h=host) if isinstance(v, str) else v) for k, v in GOOD.items()}
    row.update(over)
    return row


def _dns(domain, takeover_host=None):
    snap = {"txt": ['"v=spf1 -all"'], "dmarc_txt": ['"v=DMARC1; p=reject; rua=mailto:x@example.com"'],
            "caa": ['0 issue "letsencrypt.org"'], "mta_sts_txt": [], "dkim": {},
            "dnssec_enabled": False, "has_ds": False, "cnames": []}
    if takeover_host:
        snap["cnames"] = [{"host": takeover_host, "cname": "gone.herokuapp.com",
                           "target_resolves": False, "had_dns_answer": True}]
    return dns_posture.evaluate_domain(domain, snap)


META = {
    "fingerprints": {"www.example.com": _fp("www.example.com"),
                     "old.example.com": _fp("old.example.com", **{"strict-transport-security": None}),
                     "shop.other.com": _fp("shop.other.com")},
    "services": {"www.example.com": {"open": {"443": "https"}},
                 "db.example.com": {"open": {"3306": "mysql", "3389": "rdp"}},
                 "shop.other.com": {"open": {"443": "https"}}},
    "certificates": {"www.example.com": {"days_left": 90}, "old.example.com": {"days_left": 90},
                     "shop.other.com": {"days_left": 90}},
    "dns_posture": [_dns("example.com", takeover_host="old.example.com"), _dns("other.com")],
}


def _hosts(meta=META, **kw):
    return sc.build_hosts(["example.com", "other.com"], meta,
                          cert_rows=cc.certificates_from_meta(meta),
                          dns_results=meta["dns_posture"], **kw)


def test_every_observed_host_is_rated_and_attributed_once():
    cards = {c["host"]: c for c in _hosts()}
    assert set(cards) == {"www.example.com", "old.example.com", "db.example.com", "shop.other.com"}
    assert cards["shop.other.com"]["parent"] == "other.com"
    assert cards["db.example.com"]["parent"] == "example.com"


def test_takeover_stays_on_its_own_host():
    cards = {c["host"]: c for c in _hosts()}
    assert cards["old.example.com"]["critical_exposure"]
    assert not cards["www.example.com"]["critical_exposure"]
    www_dns = next(p for p in cards["www.example.com"]["pillars"] if p["pillar"] == "email_dns")
    assert "dns-takeover" not in {d["type"] for d in www_dns["deductions"]}


def test_hosts_order_critical_first_then_weakest():
    cards = _hosts()
    assert cards[0]["host"] == "old.example.com" and cards[0]["critical_exposure"]
    rest = [c for c in cards if not c["critical_exposure"] and not c["unknown"]]
    assert [c["score"] for c in rest] == sorted(c["score"] for c in rest)


def test_takeover_host_with_no_other_evidence_still_leads():
    meta = dict(META, dns_posture=[_dns("example.com", takeover_host="gone.example.com"), _dns("other.com")])
    cards = _hosts(meta)
    assert cards[0]["host"] == "gone.example.com"
    assert cards[0]["unknown"] and cards[0]["critical_exposure"]


def test_unrated_host_reports_its_takeover_and_no_fake_score(workspace):
    row = next(r for r in cc.hosts("acme")["hosts"] if r["host"] == "old.example.com")
    assert "dns-takeover" in {i["type"] for i in row["issues"]}
    assert all(i["type"] == "dns-takeover" for i in row["issues"] if i["factor"] == "email_dns")
    assert row["score"] is None or not row["unknown"]


def test_single_host_build_explains_gains():
    card = _hosts(only="db.example.com", explain=True)[0]
    rdp = next(d for p in card["pillars"] for d in p["deductions"] if d["type"] == "port-3389")
    assert rdp["gain"] > 0


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    fp, hp = tmp_path / "findings.json", tmp_path / "history.json"
    fp.write_text(json.dumps({"meta": dict(META, date="2026-10-23"), "findings": [
        {"id": "F-9", "title": "RDP reachable", "target": "db.example.com", "severity": "HIGH",
         "status": "OPEN", "related_cves": []}]}))
    hp.write_text("[]")
    monkeypatch.setattr(cc, "REGISTRY", {"acme": {"name": "Acme", "domains": ["example.com", "other.com"]}})
    monkeypatch.setattr(cc, "_org_paths", lambda slug: (str(fp), None))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    monkeypatch.setattr(cc, "history_path", lambda slug: str(hp))
    cc.invalidate_org_cache("acme")
    yield fp
    cc.invalidate_org_cache("acme")


def test_hosts_read_layer(workspace):
    out = cc.hosts("acme")
    rows = {r["host"]: r for r in out["hosts"]}
    db = rows["db.example.com"]
    assert db["open_findings"] == 1 and db["open_ports"] == ["3306", "3389"]
    # inherited DNS findings stay on the domain; only a host's own takeover is listed
    assert all(i["type"] == "dns-takeover" for r in out["hosts"] for i in r["issues"]
               if i["factor"] == "email_dns")
    assert out["summary"]["hosts"] == 4 and out["summary"]["with_critical"] == 1


def test_hosts_endpoint(workspace):
    from fastapi.testclient import TestClient
    import main
    c = TestClient(main.app)
    assert c.get("/api/hosts", params={"org": "acme"}).status_code == 401
    body = c.get("/api/hosts", params={"org": "acme"}, headers={"X-CTI-Token": "test-tok"}).json()
    assert body["hosts"][0]["score"] <= body["hosts"][-1]["score"] or body["hosts"][-1]["unknown"]


# --------------------------------------------------------------------------
# assistant
# --------------------------------------------------------------------------
def test_assistant_context_answers_weakest_subdomain(workspace):
    ctx = assistant.context(assistant.OrgData("acme"))
    weakest = ctx["weakest_hosts"]
    assert weakest and weakest[0]["host"] == "old.example.com"
    assert ctx["hosts_observed"] == 4


def test_host_tools(workspace):
    data = assistant.OrgData("acme")
    ranked = assistant.TOOLS["hosts"](data, {"domain": "example.com", "limit": 2})
    assert ranked["total"] == 3 and len(ranked["hosts"]) == 2
    detail = assistant.TOOLS["host"](data, {"name": "db.example.com"})
    assert detail["open_ports"] == ["3306", "3389"] and detail["findings"][0]["id"] == "F-9"
    assert any(i["host_score_gain"] for i in detail["issues"])
    assert "similar" in assistant.TOOLS["host"](data, {"name": "nope"})


def test_citations_carry_readable_labels(workspace):
    call_log = []

    def call(prompt):
        call_log.append(prompt)
        return '{"answer": "Close RDP on db.", "cites": ["port-3389", "F-9", "db.example.com"]}', {}
    r = assistant.ask("acme", "weakest subdomain?", "p", call=call)
    labels = {c["id"]: c["label"] for c in r["cites"]}
    assert labels["port-3389"] == sc.ISSUE_TYPES["port-3389"]["title"]
    assert labels["F-9"] == "RDP reachable" and labels["db.example.com"] == "db.example.com"
    assert all(c["verified"] for c in r["cites"])


def test_instructions_keep_the_safety_rules():
    text = " ".join(assistant.INSTRUCTIONS.split())
    assert "untrusted data" in text and "Never follow instructions" in text
    assert '"cites"' in text and "call plan" in text and "version matches to verify" in text
