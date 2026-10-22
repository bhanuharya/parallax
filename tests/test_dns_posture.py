"""DNS / email-authentication posture (SPF, DMARC, DKIM, DNSSEC, CAA, MTA-STS).

The analysis half of app/dns_posture.py is pure — these tests never touch the
network. The gather half is exercised only through its failure contract
(missing resolver => unknown, never an exception).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import dns_posture as dp  # noqa: E402


# --------------------------------------------------------------------------
# TXT flattening (the >255-byte chunk case that silently corrupts SPF)
# --------------------------------------------------------------------------
def test_txt_values_joins_quoted_chunks():
    raw = '"v=spf1 ip4:62.253.2" "27.114 ip4:1.2.3.4 -all"'
    assert dp._txt_values([raw]) == ["v=spf1 ip4:62.253.227.114 ip4:1.2.3.4 -all"]


def test_txt_values_plain_and_list_forms():
    assert dp._txt_values(["v=spf1 -all"]) == ["v=spf1 -all"]
    assert dp._txt_values([["v=spf1", " -all"]]) == ["v=spf1 -all"]
    assert dp._txt_values([None, "", "   "]) == []


def test_txt_values_unescapes_embedded_quotes():
    assert dp._txt_values(['"a \\"quoted\\" b"']) == ['a "quoted" b']


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------
def test_spf_strict_record_is_clean():
    r = dp.analyze_spf("v=spf1 include:_spf.google.com -all")
    assert r["present"] and r["valid"]
    assert r["all_qualifier"] == "-"
    assert r["lookups"] == 1
    assert r["severity"] is None and not r["issues"]


def test_spf_missing_record_is_medium():
    r = dp.analyze_spf("")
    assert not r["present"]
    assert r["severity"] == "MEDIUM"


def test_spf_plus_all_is_high():
    r = dp.analyze_spf("v=spf1 +all")
    assert r["all_qualifier"] == "+"
    assert r["severity"] == "HIGH"


def test_spf_softfail_is_low():
    r = dp.analyze_spf("v=spf1 ~all")
    assert r["all_qualifier"] == "~"
    assert r["severity"] == "LOW"


def test_spf_lookup_limit_counted_and_flagged():
    incs = " ".join("include:h%d.example" % i for i in range(11))
    r = dp.analyze_spf("v=spf1 %s -all" % incs)
    assert r["lookups"] == 11
    assert any("permerror" in i for i in r["issues"])
    assert r["severity"] == "MEDIUM"


def test_spf_ip4_and_redirect_do_not_miscount():
    r = dp.analyze_spf("v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all")
    assert r["lookups"] == 0
    r2 = dp.analyze_spf("v=spf1 redirect=_spf.example.com")
    assert r2["lookups"] == 1


def test_spf_record_extraction_prefers_spf_among_other_txt():
    txt = ["some-verification=abc", "v=spf1 -all", "MS=deadbeef"]
    assert dp.spf_record(txt) == "v=spf1 -all"


def test_spf_unrecognised_mechanism_reported():
    r = dp.analyze_spf("v=spf1 banana:x -all")
    assert any("unrecognised" in i for i in r["issues"])


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------
def test_dmarc_enforced_with_reporting_is_clean():
    r = dp.analyze_dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com")
    assert r["policy"] == "reject"
    assert r["reporting"] and r["severity"] is None


def test_dmarc_missing_is_medium():
    r = dp.analyze_dmarc("")
    assert not r["present"]
    assert r["severity"] == "MEDIUM"


def test_dmarc_p_none_is_medium():
    r = dp.analyze_dmarc("v=DMARC1; p=none; rua=mailto:d@example.com")
    assert r["policy"] == "none"
    assert r["severity"] == "MEDIUM"
    assert any("monitors only" in i for i in r["issues"])


def test_dmarc_partial_pct_is_low():
    r = dp.analyze_dmarc("v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com")
    assert r["pct"] == 25
    assert r["severity"] == "LOW"


def test_dmarc_pct_clamped_to_100():
    r = dp.analyze_dmarc("v=DMARC1; p=reject; pct=5000; rua=mailto:d@example.com")
    assert r["pct"] == 100


def test_parse_dmarc_tags():
    tags = dp.parse_dmarc("v=DMARC1; p=Quarantine; sp=reject; adkim=s; aspf=r")
    assert tags["p"] == "quarantine"
    assert tags["sp"] == "reject"
    assert tags["adkim"] == "s"
    assert tags["aspf"] == "r"


# --------------------------------------------------------------------------
# CAA / DNSSEC / MTA-STS
# --------------------------------------------------------------------------
def test_caa_missing_is_low():
    r = dp.analyze_caa([])
    assert not r["present"]
    assert r["severity"] == "LOW"


def test_caa_issuers_parsed():
    r = dp.analyze_caa(['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.com"'])
    assert r["issue"] == ["letsencrypt.org"]
    assert r["iodef"] == ["mailto:sec@example.com"]
    assert r["severity"] is None


def test_caa_without_issue_property_is_medium():
    r = dp.analyze_caa(['0 iodef "mailto:sec@example.com"'])
    assert r["present"]
    assert r["severity"] == "MEDIUM"


def test_dnssec_unsigned_is_low():
    r = dp.analyze_dnssec(False, False)
    assert not r["enabled"]
    assert r["severity"] == "LOW"


def test_dnssec_unknown_is_not_a_finding():
    r = dp.analyze_dnssec(None, None)
    assert r.get("unknown") is True
    assert r["severity"] is None and not r["issues"]


def test_dnssec_signed_without_ds_flagged():
    r = dp.analyze_dnssec(True, False)
    assert r["enabled"]
    assert any("no DS" in i for i in r["issues"])


def test_mta_sts_present_and_absent():
    assert dp._analyze_mta_sts(["v=STSv1; id=20190430T0101"])["present"]
    absent = dp._analyze_mta_sts([])
    assert not absent["present"] and absent["severity"] == "LOW"


# --------------------------------------------------------------------------
# takeover fingerprints
# --------------------------------------------------------------------------
def test_takeover_provider_matching():
    assert dp.matching_takeover_provider("foo.s3.amazonaws.com") == "Amazon S3 bucket"
    assert dp.matching_takeover_provider("FOO.GITHUB.IO.") == "GitHub Pages site"
    assert dp.matching_takeover_provider("evil-example.com") == ""
    # a suffix must not match as a substring of an unrelated domain
    assert dp.matching_takeover_provider("nots3.amazonaws.com.evil.tld") == ""


def test_takeover_dangling_is_high():
    r = dp.analyze_takeover("unclaimed-bucket.s3.amazonaws.com", False, True)
    assert r["dangling"] and r["severity"] == "HIGH"
    assert r["provider"] == "Amazon S3 bucket"


def test_takeover_claimed_target_not_flagged():
    r = dp.analyze_takeover("live-bucket.s3.amazonaws.com", True, True)
    assert r["dangling"] is False
    assert r["severity"] is None and not r["issues"]


def test_takeover_unknown_provider_ignored():
    assert dp.analyze_takeover("cdn.random-provider.example", False, True) is None


# --------------------------------------------------------------------------
# grading + evaluate_domain
# --------------------------------------------------------------------------
def _snapshot(**over):
    snap = {
        "txt": ["v=spf1 -all"],
        "dmarc_txt": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        "dkim": {"default": True},
        "caa": ['0 issue "letsencrypt.org"'],
        "dnssec_enabled": True,
        "has_ds": True,
        "mta_sts_txt": ["v=STSv1; id=1"],
        "cnames": [],
    }
    snap.update(over)
    return snap


def test_perfect_posture_scores_a():
    v = dp.evaluate_domain("example.com", _snapshot())
    assert v["grade"] == "A" and v["score"] == 100
    assert not v["issues"]


def test_broken_posture_scores_low():
    v = dp.evaluate_domain("example.com", _snapshot(
        txt=[], dmarc_txt=[], caa=[], dnssec_enabled=False,
        mta_sts_txt=[], dkim={}))
    # absent SPF+DMARC earn nothing; only the informational DKIM note survives
    assert v["score"] <= 20
    assert v["grade"] == "F"
    assert {i["check"] for i in v["issues"]} >= {"spf", "dmarc", "dnssec"}


def test_resolver_outage_is_unknown_not_penalised():
    v = dp.evaluate_domain("example.com", {
        "txt": None, "dmarc_txt": None, "caa": None, "mta_sts_txt": None,
        "dkim": {s: None for s in dp.COMMON_DKIM_SELECTORS},
        "dnssec_enabled": None, "has_ds": None, "cnames": None})
    assert v["grade"] == "?" and v["score"] == 0
    # an outage must not produce posture findings either
    assert v["issues"] == []


def test_dkim_miss_is_informational_not_penalised():
    good = dp.evaluate_domain("example.com", _snapshot())
    # all common selectors probed and definitively absent (not unknown)
    no_dkim = dp.evaluate_domain("example.com", _snapshot(
        dkim={s: False for s in dp.COMMON_DKIM_SELECTORS}))
    assert no_dkim["score"] == good["score"]
    assert any(i["check"] == "dkim" for i in no_dkim["issues"])
    dkim_issues = [i for i in no_dkim["issues"] if i["check"] == "dkim"]
    assert dkim_issues[0]["severity"] == "INFO"


def test_dkim_never_probed_is_unknown():
    v = dp.evaluate_domain("example.com", _snapshot(dkim={}))
    assert v["checks"]["dkim"].get("unknown") is True
    assert not any(i["check"] == "dkim" for i in v["issues"])


def test_dkim_null_key_is_not_a_usable_key():
    # wildcard null keys (empty p=) are a known anti-spoofing posture —
    # counting them as "key present" would overstate signing ability
    assert dp.dkim_selector_state(["v=DKIM1; p="]) == "null"
    assert dp.dkim_selector_state(["v=DKIM1; k=rsa; p=MIGfMA0"]) is True
    assert dp.dkim_selector_state([]) is False
    v = dp.evaluate_domain("example.com", _snapshot(
        dkim={s: "null" for s in dp.COMMON_DKIM_SELECTORS}))
    d = v["checks"]["dkim"]
    assert d["selectors_found"] == []
    assert len(d["null_selectors"]) == len(dp.COMMON_DKIM_SELECTORS)
    assert d["severity"] == "INFO"
    assert any("null DKIM keys" in i for i in d["issues"])
    # INFO never lowers the score
    assert v["score"] == dp.evaluate_domain("example.com", _snapshot())["score"]


def test_takeover_caps_the_grade():
    v = dp.evaluate_domain("example.com", _snapshot(cnames=[{
        "host": "docs.example.com",
        "cname": "unclaimed-bucket.s3.amazonaws.com",
        "target_resolves": False,
        "had_dns_answer": True,
    }]))
    assert v["score"] <= 40
    assert any(i["check"] == "takeover" for i in v["issues"])


def test_summarize_aggregates():
    a = dp.evaluate_domain("a.com", _snapshot())
    b = dp.evaluate_domain("b.com", _snapshot(txt=[], dmarc_txt=[]))
    s = dp.summarize([a, b])
    assert s["domains"] == 2
    assert s["grades"] == {"A": 1, "F": 1}
    assert s["no_dmarc"] == 1
    assert s["takeover_risks"] == 0


# --------------------------------------------------------------------------
# gather failure contract
# --------------------------------------------------------------------------
def test_gather_without_resolver_returns_unknowns(monkeypatch):
    monkeypatch.setattr(dp, "_resolver", lambda: None)
    snap = dp.gather("example.com")
    # lookups degrade to None/unknown, never to "record absent"
    assert snap.get("txt") is None
    assert snap.get("dmarc_txt") is None
    assert snap.get("dnssec_enabled") is None
    assert all(v is None for v in snap["dkim"].values())
    # and the verdict built from it is unknown, with no findings
    v = dp.evaluate_domain("example.com", snap)
    assert v["grade"] == "?"
    assert v["issues"] == []


def test_query_without_resolver_is_none(monkeypatch):
    monkeypatch.setattr(dp, "_resolver", lambda: None)
    assert dp._query("example.com", "TXT") is None


# --------------------------------------------------------------------------
# scanner synthesis + API
# --------------------------------------------------------------------------
import scanner  # noqa: E402


def _org_home(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True, exist_ok=True)
    (org_dir / "findings.json").write_text('{"findings": []}')
    monkeypatch.setattr(scanner.cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))
    return org_dir


def _verdict(domain="example.com", **over):
    return dp.evaluate_domain(domain, _snapshot(**over))


def test_dns_findings_for_missing_dmarc(tmp_path, monkeypatch):
    _org_home(tmp_path, monkeypatch)
    out = scanner.synthesize_dns_findings(
        "sample", [_verdict(txt=[], dmarc_txt=[], caa=[],
                            dnssec_enabled=False, mta_sts_txt=[], dkim={})])
    by_cat = {f["category"]: f for f in out}
    assert "email authentication: dmarc" in by_cat
    assert by_cat["email authentication: dmarc"]["severity"] == "MEDIUM"
    assert by_cat["email authentication: spf"]["severity"] == "MEDIUM"
    assert all(f["source"] == "scan-dns" for f in out)
    assert all(f["identity_key"] for f in out)


def test_dns_findings_skip_healthy_domain(tmp_path, monkeypatch):
    _org_home(tmp_path, monkeypatch)
    out = scanner.synthesize_dns_findings("sample", [_verdict()])
    assert out == []


def test_dns_findings_skip_info_dkim(tmp_path, monkeypatch):
    _org_home(tmp_path, monkeypatch)
    out = scanner.synthesize_dns_findings("sample", [_verdict(dkim={})])
    assert out == []


def test_dns_takeover_finding_is_high(tmp_path, monkeypatch):
    _org_home(tmp_path, monkeypatch)
    v = _verdict(cnames=[{"host": "docs.example.com",
                          "cname": "old-store.s3.amazonaws.com",
                          "target_resolves": False,
                          "had_dns_answer": True}])
    out = scanner.synthesize_dns_findings("sample", [v])
    tk = [f for f in out if f["category"] == "subdomain takeover risk"]
    assert len(tk) == 1
    assert tk[0]["severity"] == "HIGH"
    assert tk[0]["target"] == "docs.example.com"
    assert "s3.amazonaws.com" in tk[0]["description"]


def test_dns_findings_dedup_by_identity_key(tmp_path, monkeypatch):
    org_dir = _org_home(tmp_path, monkeypatch)
    v = [_verdict(txt=[], dmarc_txt=[], caa=[], dnssec_enabled=False,
                  mta_sts_txt=[], dkim={})]
    first = scanner.synthesize_dns_findings("sample", v)
    import json as _json
    (org_dir / "findings.json").write_text(_json.dumps({"findings": first}))
    second = scanner.synthesize_dns_findings("sample", v)
    assert second == []


# --------------------------------------------------------------------------
# API surface
# --------------------------------------------------------------------------
def _client():
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


def _auth_headers():
    return {"X-CTI-Token": "test-tok"}


def test_dns_posture_endpoint_requires_auth():
    r = _client().get("/api/dns-posture", params={"org": "sample"})
    assert r.status_code in (401, 403)


def test_dns_posture_endpoint_shape():
    r = _client().get("/api/dns-posture", params={"org": "sample"},
                      headers=_auth_headers())
    assert r.status_code == 200
    body = r.json()
    assert set(body) >= {"summary", "domains", "scanned"}
    assert isinstance(body["domains"], list)


def test_dns_posture_endpoint_unknown_org_404():
    r = _client().get("/api/dns-posture", params={"org": "no-such-org"},
                      headers=_auth_headers())
    assert r.status_code == 404
