"""External posture rating: factor model, exact projections, planner, portfolio.

Properties defended here, beyond the base rating rules in test_scorecard.py:

  - every deduction belongs to a catalogued issue type with a fix;
  - web factors judge only what was actually received (no 5xx, no guesses
    about truncated headers), and unknown stays unknown;
  - a projected gain is exactly what re-scoring without the issue produces,
    never negative, and honours the critical cap;
  - DNS attribution sums to the posture score it explains;
  - the planner and portfolio are read-only and auth-gated.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402
import dns_posture  # noqa: E402
import posture  # noqa: E402
import scorecard as sc  # noqa: E402

SEV = {"CVE-A": "CRITICAL", "CVE-B": "CRITICAL", "CVE-H": "HIGH"}
CLEAN_WEB = {"url": "https://h.example.com", "code": "200", "server": "nginx",
             "strict-transport-security": "max-age=31536000",
             "content-security-policy": "default-src 'self'",
             "x-content-type-options": "nosniff", "assets": []}


def web(**over):
    row = dict(CLEAN_WEB, host="h.example.com")
    row.update(over)
    return {k: v for k, v in row.items() if v is not None}


def full_card(software=(), web_rows=None, dns=None, services=None, certs=None, exclude=()):
    return sc.scorecard_for_domain(
        "example.com", list(software),
        certs if certs is not None else [{"host": "h.example.com", "issues": []}],
        dns or {"domain": "example.com", "grade": "A", "score": 100, "issues": []},
        services if services is not None else [{"host": "h.example.com", "open": {}}],
        SEV, software_assessed=True,
        web_rows=web_rows if web_rows is not None else [web()], exclude=exclude)


def types(pillar):
    return {d["type"] for d in pillar["deductions"]}


# --------------------------------------------------------------------------
# model shape
# --------------------------------------------------------------------------
def test_weights_cover_every_factor_and_sum_to_100():
    assert sum(sc.WEIGHTS.values()) == 100
    assert set(sc.WEIGHTS) == set(sc.PILLAR_LABELS)


def test_every_issue_type_is_catalogued_with_a_fix():
    for key, info in sc.ISSUE_TYPES.items():
        assert info["factor"] in sc.WEIGHTS, key
        assert info["severity"] in ("critical", "high", "medium", "low"), key
        assert info["title"] and info["why"] and info["fix"], key


def test_every_emitted_deduction_type_is_in_the_catalog():
    card = full_card(
        software=[{"host": "h.example.com", "product": "x", "version": "1",
                   "cve_count": 1, "related_cves": ["CVE-A"]}],
        web_rows=[web(url="http://h.example.com", server="Apache/2.4.41",
                      **{"x-powered-by": "PHP/7.4.3", "content-security-policy": None,
                         "x-content-type-options": None},
                      assets=[{"host": "cdn.polyfill.io", "kind": "script"}])],
        certs=[{"host": "h.example.com", "issues": ["expired", "self-signed"]}],
        services=[{"host": "h.example.com", "open": {"3389": "rdp"}}],
        dns={"domain": "example.com", "grade": "F", "score": 30,
             "issues": [{"check": "dmarc", "severity": "MEDIUM", "message": "no DMARC"}]})
    emitted = {d["type"] for p in card["pillars"] for d in p["deductions"]}
    assert emitted and emitted <= set(sc.ISSUE_TYPES)


def test_factor_verdicts_carry_their_own_grade():
    card = full_card(certs=[{"host": "h.example.com", "issues": ["expired"]}])
    certs = next(p for p in card["pillars"] if p["pillar"] == "certificates")
    assert certs["score"] == 100 - sc._CERT_POINTS["expired"]
    assert certs["grade"] == sc.grade_for(certs["score"])
    assert certs["earned"] == round(certs["max"] * certs["score"] / 100.0, 1)


# --------------------------------------------------------------------------
# application security / disclosure / dependencies
# --------------------------------------------------------------------------
def test_application_factor_checks():
    p = sc.application_pillar([web(url="http://h.example.com",
                                   **{"strict-transport-security": None})])
    assert "no-https" in types(p) and "no-hsts" not in types(p)
    p = sc.application_pillar([web(**{"strict-transport-security": "max-age=0"})])
    assert "no-hsts" in types(p)
    p = sc.application_pillar([web(**{"content-security-policy": None})])
    assert {"no-csp", "no-frame-protection"} <= types(p)
    p = sc.application_pillar([web(**{"x-frame-options": "DENY", "content-security-policy": None})])
    assert "no-frame-protection" not in types(p)


def test_any_csp_counts_as_frame_protection_because_capture_is_truncated():
    p = sc.application_pillar([web(**{"content-security-policy": "script-src 'self'"})])
    assert "no-frame-protection" not in types(p)


def test_page_headers_are_not_expected_on_redirects():
    p = sc.application_pillar([web(code="301", **{"content-security-policy": None,
                                                  "x-content-type-options": None})])
    assert types(p) == set()


def test_cookie_secure_flag_parsing():
    assert types(sc.application_pillar([web(cookies=["sid (HttpOnly,Secure,SameSite)"])])) == set()
    assert "insecure-cookie" in types(sc.application_pillar([web(cookies=["sid (HttpOnly)"])]))
    assert "insecure-cookie" in types(sc.application_pillar([web(cookies=["sid"])]))


def test_error_pages_and_missing_responses_leave_web_factors_unknown():
    for rows in (None, [], [web(code="503")], [{"host": "h.example.com"}]):
        assert sc.application_pillar(rows)["unknown"] is True
        assert sc.disclosure_pillar(rows)["unknown"] is True


def test_disclosure_factor_checks():
    p = sc.disclosure_pillar([web(server="Apache/2.4.41 (Ubuntu)",
                                  **{"x-powered-by": "Express", "x-aspnet-version": "4.0.30319"},
                                  generator="WordPress 6.4.2")])
    assert types(p) == {"server-version", "powered-by", "aspnet-version", "generator-version"}
    assert types(sc.disclosure_pillar([web(server="cloudflare")])) == set()
    assert types(sc.disclosure_pillar([web(server="ECS (dcb/7F84)")])) == set()


def test_web_issue_points_scale_with_hosts_up_to_a_cap():
    rows = [web(host="h%d.example.com" % i, **{"strict-transport-security": None})
            for i in range(10)]
    item = next(d for d in sc.application_pillar(rows)["deductions"] if d["type"] == "no-hsts")
    per_host, cap = sc._WEB_POINTS["no-hsts"]
    assert item["count"] == 10 and item["points"] == cap
    assert "+7 more" in item["detail"]


def test_dependencies_factor_unknown_until_markup_examined():
    assert sc.dependencies_pillar([web(assets=None)])["unknown"] is True
    clean = sc.dependencies_pillar([web()])
    assert clean["unknown"] is False and clean["score"] == 100


def test_compromised_cdn_caps_the_rating_like_a_critical_cve():
    card = full_card(web_rows=[web(assets=[{"host": "cdn.polyfill.io", "kind": "script"}])])
    assert card["critical_exposure"] and card["score"] <= 60
    fixed = full_card(web_rows=[web(assets=[{"host": "cdn.polyfill.io", "kind": "script"}])],
                      exclude={"dep-compromised"})
    assert not fixed["critical_exposure"]


# --------------------------------------------------------------------------
# exact projections
# --------------------------------------------------------------------------
def _crit(host, cve):
    return {"host": host, "product": "app", "version": "1", "cve_count": 1, "related_cves": [cve]}


def test_gain_equals_rescoring_without_the_item():
    card = full_card(certs=[{"host": "h.example.com", "issues": ["expired"]}],
                     services=[{"host": "h.example.com", "open": {"6379": "redis"}}])
    for issue in card["issues"]:
        code = next(d["code"] for p in card["pillars"] for d in p["deductions"]
                    if d["label"] == issue["label"])
        after = full_card(certs=[{"host": "h.example.com", "issues": ["expired"]}],
                          services=[{"host": "h.example.com", "open": {"6379": "redis"}}],
                          exclude={code})
        assert issue["gain"] == after["score"] - card["score"] > 0


def test_fixing_one_of_two_criticals_gains_nothing_while_capped():
    card = full_card(software=[_crit("a.example.com", "CVE-A"), _crit("b.example.com", "CVE-B")])
    assert card["critical_cap"]
    assert all(i["gain"] == 0 for i in card["issues"] if i["type"] == "vuln-critical")
    row = next(t for t in card["issue_types"] if t["type"] == "vuln-critical")
    assert row["gain"] > 0 and row["count"] == 2


def test_gains_are_never_negative():
    card = full_card(software=[_crit("a.example.com", "CVE-A")],
                     certs=[{"host": "h.example.com", "issues": ["expired", "expiring soon"]}],
                     web_rows=[web(url="http://h.example.com")])
    assert all(i["gain"] >= 0 for i in card["issues"])
    assert all(t["gain"] >= 0 for t in card["issue_types"])


def test_budgeted_items_refill_when_one_is_fixed():
    """Fixing one deduction lets a previously truncated one count, so its
    gain is smaller than its points — the honest answer."""
    rows = [{"host": "h%d.example.com" % i, "product": "lib", "version": "1",
             "cve_count": 1, "related_cves": ["CVE-H"]} for i in range(8)]
    card = full_card(software=rows)
    item = card["issues"][0]
    weighted = item["points"] * sc.WEIGHTS["vulnerability"] / 100.0
    assert item["gain"] < weighted


# --------------------------------------------------------------------------
# DNS attribution
# --------------------------------------------------------------------------
def _dns_verdict():
    snap = {"txt": ["v=spf1 include:_spf.google.com ~all"], "dmarc_txt": ["v=DMARC1; p=none"],
            "caa": [], "mta_sts_txt": [], "dkim": {}, "dnssec_enabled": False, "has_ds": False,
            "cnames": [{"host": "old.example.com", "cname": "gone.herokuapp.com",
                        "target_resolves": False, "had_dns_answer": True}]}
    return dns_posture.evaluate_domain("example.com", snap)


def test_dns_attribution_sums_to_the_points_lost():
    verdict = _dns_verdict()
    p = sc.email_dns_pillar(verdict)
    assert p["score"] == verdict["score"]
    assert sum(d["points"] for d in p["deductions"]) == 100 - verdict["score"]
    assert "dns-takeover" in types(p)


def test_dns_projection_uses_the_posture_model():
    verdict = _dns_verdict()
    fixed = sc.email_dns_pillar(verdict, exclude={"dns-dmarc"})
    checks = dict(verdict["checks"], dmarc={"present": True, "severity": None, "issues": []})
    assert fixed["score"] == dns_posture._grade(checks, [])[0]
    assert "dns-dmarc" not in types(fixed)


def test_check_credit_matches_grade():
    verdict = _dns_verdict()
    assert dns_posture.check_credit({"unknown": True}) is None
    assert dns_posture.check_credit({"missing": True}) == 0.0
    assert dns_posture._grade(verdict["checks"], [])[0] == verdict["score"]


# --------------------------------------------------------------------------
# org rollups
# --------------------------------------------------------------------------
def test_summary_factors_never_borrow_a_number():
    card = sc.scorecard_for_domain("example.com", software_assessed=True,
                                   cert_rows=[{"host": "h.example.com", "issues": []}])
    factors = {f["factor"]: f for f in sc.summarize([card])["factors"]}
    assert factors["certificates"]["score"] == 100
    assert factors["exposed"]["score"] is None and factors["exposed"]["grade"] == "?"


def test_org_issues_gain_matches_rebuild():
    cards_in = [_crit("h.example.com", "CVE-A")]
    meta = {"fingerprints": {"h.example.com": web()},
            "services": {"h.example.com": {"open": {"3389": "rdp"}}}}

    def rebuild(more=()):
        return sc.build(["example.com"], meta, software_rows=cards_in,
                        severity_map=SEV, exclude=more, explain=False)
    cards = sc.build(["example.com"], meta, software_rows=cards_in, severity_map=SEV)
    issues = sc.org_issues(cards, rebuild)
    base = sc.summarize(cards)["average_score"]
    for row in issues:
        assert row["gain"] == sc.summarize(rebuild({row["type"]}))["average_score"] - base
        assert row["fix"] and row["domains"][0]["domain"] == "example.com"
    assert issues[0]["type"] == "vuln-critical"


# --------------------------------------------------------------------------
# history trend and actions
# --------------------------------------------------------------------------
def test_trend_uses_only_current_model_and_assessed_domains():
    def ev(version, score, unknown=False):
        return {"kind": "scan", "ts": "t%d" % score, "posture": {"version": version, "domains": [
            {"domain": "example.com", "score": score, "unknown": unknown}]}}
    scans = [ev(1, 10), ev(posture.MODEL_VERSION, 70), ev(posture.MODEL_VERSION, 0, unknown=True),
             ev(posture.MODEL_VERSION, 80)]
    assert [p["score"] for p in posture.trend(scans)] == [70, 80]


def test_actions_use_catalog_fixes_and_rank_critical_first():
    card = full_card(dns=_dns_verdict(),
                     services=[{"host": "h.example.com", "open": {"3389": "rdp"}}])
    actions = posture.action_plan([card])
    assert actions[0]["type"] == "dns-takeover" and actions[0]["rank"] == 0
    rdp = next(a for a in actions if a["type"] == "port-3389")
    assert rdp["next_step"] == sc.ISSUE_TYPES["port-3389"]["fix"]
    same_rank = [a["gain"] for a in actions if a["rank"] == 2]
    assert same_rank == sorted(same_rank, reverse=True)


# --------------------------------------------------------------------------
# API: planner, portfolio, naming
# --------------------------------------------------------------------------
@pytest.fixture
def workspace(tmp_path, monkeypatch):
    fp, hp = tmp_path / "findings.json", tmp_path / "history.json"
    fp.write_text(json.dumps({"meta": {
        "date": "2026-10-23",
        "fingerprints": {"www.example.com": web(host=None, url="https://www.example.com",
                                                **{"strict-transport-security": None})},
        "services": {"www.example.com": {"open": {"3389": "rdp"}}},
        "certificates": {"www.example.com": {"days_left": 200, "chain_trusted": True,
                                             "hostname_ok": True}}}, "findings": []}))
    hp.write_text("[]")
    monkeypatch.setattr(cc, "REGISTRY", {"acme": {"name": "Acme", "domains": ["example.com"]},
                                         "beta": {"name": "Beta", "domains": ["beta.example"]}})
    monkeypatch.setattr(cc, "_org_paths", lambda slug: (str(fp), None))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    monkeypatch.setattr(cc, "history_path", lambda slug: str(hp))
    for slug in ("acme", "beta"):
        cc.invalidate_org_cache(slug)
    yield fp, hp
    for slug in ("acme", "beta"):
        cc.invalidate_org_cache(slug)


def _client():
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


AUTH = {"X-CTI-Token": "test-tok"}


def test_posture_route_matches_legacy_route(workspace):
    c = _client()
    a = c.get("/api/posture", params={"org": "acme"}, headers=AUTH).json()
    b = c.get("/api/scorecard", params={"org": "acme"}, headers=AUTH).json()
    assert a == b and a["summary"]["factors"] and a["issues"]


def test_planner_projects_selected_fixes(workspace):
    c = _client()
    assert c.get("/api/posture/plan", params={"org": "acme", "fix": "port-3389"}).status_code == 401
    for bad in ("nope", "port-3389,<script>", ",".join(["no-hsts"] * 51)):
        r = c.get("/api/posture/plan", params={"org": "acme", "fix": bad}, headers=AUTH)
        assert r.status_code == 400
    r = c.get("/api/posture/plan", params={"org": "acme", "fix": "port-3389,no-hsts"},
              headers=AUTH).json()
    assert r["fix"] == ["no-hsts", "port-3389"]
    assert r["after"]["average_score"] > r["before"]["average_score"]
    assert r["domains"][0]["after"] >= r["domains"][0]["before"]
    none = c.get("/api/posture/plan", params={"org": "acme"}, headers=AUTH).json()
    assert none["after"] == none["before"]


def test_planner_and_reads_never_write_history(workspace):
    fp, hp = workspace
    before = hp.read_bytes()
    c = _client()
    c.get("/api/posture/plan", params={"org": "acme", "fix": "port-3389"}, headers=AUTH)
    c.get("/api/portfolio", headers=AUTH)
    assert hp.read_bytes() == before


def test_portfolio_lists_every_org(workspace):
    c = _client()
    assert c.get("/api/portfolio").status_code == 401
    rows = c.get("/api/portfolio", headers=AUTH).json()["orgs"]
    assert [r["slug"] for r in rows] == ["acme", "beta"]
    acme = rows[0]
    assert acme["summary"]["assessed"] == 1 and acme["issues"].get("high", 0) >= 1
    assert rows[1]["summary"]["assessed"] == 0


def test_report_shows_factors_and_issues_without_scorecard_naming(workspace, monkeypatch):
    import main
    monkeypatch.setattr(main, "_CHROMIUM", None)
    r = _client().get("/api/orgs/acme/report.html", headers=AUTH)
    assert r.status_code == 200
    assert "Risk factors" in r.text and "Top issues" in r.text
    assert "scorecard" not in r.text.lower()


def test_subdomain_takeover_caps_the_rating_and_stays_listed():
    card = full_card(dns=_dns_verdict())
    assert card["critical_exposure"] and card["score"] <= 60
    assert any(i["type"] == "dns-takeover" for i in card["issues"])
    assert not full_card(dns=_dns_verdict(), exclude={"dns-takeover"})["critical_exposure"]


def test_every_factor_has_action_guidance():
    """A factor without guidance crashes action_plan for every org that has
    a deduction in it (found with realistic demo data, missed by unit cards)."""
    assert set(posture._GUIDANCE) == set(sc.WEIGHTS)


def test_action_plan_covers_dependency_issues():
    card = full_card(web_rows=[web(assets=[
        {"host": "cdnjs.cloudflare.com", "kind": "script", "library": "angularjs", "version": "1.7.9",
         "cdn": "cdnjs", "sri": False, "pinned": True}])])
    actions = posture.action_plan([card])
    types = {a["type"] for a in actions}
    assert {"dep-eol", "dep-no-sri"} <= types
