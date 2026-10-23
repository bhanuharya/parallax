"""Live advisories from cve.now.

What these tests defend:

  - opt-in: nothing is fetched unless CTI_CVE_NOW is set, and only package
    names, versions and CVE ids are ever sent;
  - responses are untrusted: ids are validated and text is bounded;
  - fail-open: an outage yields a partial record, never an exception;
  - the read path joins captured intel without any network call, live CVSS
    overrides the curated map, and KEV-listed CVEs rank as urgent.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402
import live_cve  # noqa: E402
import posture  # noqa: E402
import scorecard as sc  # noqa: E402


def entry(cid, cvss=6.9, kev=False, package="jquery", ranges=None, **extra):
    e = {
        "id": cid, "aliases": ["GHSA-gxr4-xjj5-5px2", "not an id"], "title": "t " * 200,
        "summary": None, "originalDescription": "d",
        "severity": {"cvss": cvss, "vector": "CVSS:3.1/AV:N", "source": "cna"} if cvss is not None else None,
        "statedSeverity": None,
        "exploitation": {"kev": {"dateAdded": "2025-01-23", "dueDate": "2025-02-13"} if kev else None,
                         "epssReached": None, "exploitDb": None},
        "affected": [{"vendor": "jquery", "product": "jQuery", "ranges": [{"introduced": "0", "fixed": "9.9"}]},
                     {"ecosystem": "npm", "package": package,
                      "ranges": ranges or [{"introduced": "1.0.3", "fixed": "3.5.0"}]}],
        "publishedAt": "2020-04-29T00:00:00.000Z",
    }
    e.update(extra)
    return e


@pytest.fixture
def http(monkeypatch, tmp_path):
    """Route cve.now calls to canned answers and record every URL."""
    calls = []
    answers = {}

    def fake(url, timeout=15, headers=()):
        calls.append(url)
        for key, value in answers.items():
            if key in url:
                if isinstance(value, Exception):
                    raise value
                return value
        return {}
    monkeypatch.setattr(live_cve.cve_match, "_http_get_json", fake)
    monkeypatch.setattr(live_cve, "_cache_path", lambda: str(tmp_path / "cache.json"))
    return calls, answers


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def test_enabled_is_opt_in(monkeypatch):
    monkeypatch.delenv("CTI_CVE_NOW", raising=False)
    assert not live_cve.enabled()
    monkeypatch.setenv("CTI_CVE_NOW", "1")
    assert live_cve.enabled()


def test_compact_validates_and_bounds():
    rec = live_cve.compact(entry("CVE-2020-11023", kev=True), ("npm", "jquery", "3.4.1"))
    assert rec["id"] == "CVE-2020-11023"
    assert rec["aliases"] == ["GHSA-GXR4-XJJ5-5PX2"]
    assert len(rec["title"]) <= 200
    assert rec["kev"] == {"added": "2025-01-23", "due": "2025-02-13"}
    assert rec["fixed"] == "3.5.0" and rec["published"] == "2020-04-29"
    assert live_cve.compact(entry("<script>")) is None
    assert live_cve.compact("nope") is None
    bad = live_cve.compact(entry("CVE-2020-1", cvss=99))
    assert bad is None or bad["cvss"] is None


def test_fixed_version_picks_the_containing_range():
    ranges = [{"introduced": "4.0.0", "fixed": "4.1.2"}, {"introduced": "2.3.0", "fixed": "3.4.0"}]
    e = entry("CVE-2018-14040", package="bootstrap", ranges=ranges)
    assert live_cve.compact(e, ("npm", "bootstrap", "3.3.7"))["fixed"] == "3.4.0"
    assert live_cve.compact(e, ("npm", "bootstrap", "4.0.0"))["fixed"] == "4.1.2"
    open_ended = entry("CVE-2024-6485", package="bootstrap",
                       ranges=[{"introduced": "1.4.0", "lastAffected": "3.4.1"}])
    assert live_cve.compact(open_ended, ("npm", "bootstrap", "3.3.7"))["fixed"] is None


@pytest.mark.parametrize("cvss,stated,expected", [
    (9.8, None, "CRITICAL"), (7.2, None, "HIGH"), (6.9, None, "MEDIUM"), (3.1, None, "LOW"),
    (None, "moderate", "MEDIUM"), (None, None, None)])
def test_severity_of(cvss, stated, expected):
    rec = live_cve.compact(entry("CVE-2020-11022", cvss=cvss, statedSeverity=stated))
    assert live_cve.severity_of(rec) == expected


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------
def test_package_lookup_batches_routes_and_caches(http):
    calls, answers = http
    packages = [("npm", "lib%d" % i, "1.0.%d" % i) for i in range(11)] + [("npm", "jquery", "3.4.1")]
    e = entry("CVE-2020-11023", kev=True)
    e["matched"] = {"ecosystem": "npm", "name": "jquery", "version": "3.4.1"}
    answers["/stack?"] = {"packages": 10, "entries": [e]}
    found, errors = live_cve.lookup_packages(packages)
    assert errors == 0 and len(calls) == 2              # 12 packages, batches of 10
    assert [r["id"] for r in found["npm:jquery@3.4.1"]] == ["CVE-2020-11023"]
    assert found["npm:lib0@1.0.0"] == []
    # nothing but package coordinates leaves the host
    assert all(c.startswith("https://cve.now/stack?format=json&p=npm:") for c in calls)
    live_cve.lookup_packages(packages)
    assert len(calls) == 2, "fresh cache must answer without network"


def test_failed_batch_is_counted_not_raised(http):
    calls, answers = http
    answers["/stack?"] = {}
    found, errors = live_cve.lookup_packages([("npm", "jquery", "3.4.1")])
    assert found == {} and errors == 1


def test_entry_lookups_respect_the_cap(http):
    calls, answers = http
    answers["/api/v1/entries/"] = entry("CVE-2021-23017", cvss=7.7)
    ids = ["CVE-2021-%05d" % i for i in range(5)] + ["not-an-id"]
    found, errors = live_cve.lookup_entries(ids, cap=3)
    assert len(calls) == 3 and errors == 0


def test_observed_packages_are_exact_npm_versions_only():
    fps = {"a": {"versions": [{"product": "jquery", "version": "3.4.1"},
                              {"product": "nginx", "version": "1.18.0"},
                              {"product": "vue", "version": "2"},
                              {"product": "popper.js", "version": "2.11.8"}]},
           "b": {"versions": [{"product": "jquery", "version": "3.4.1"}]}}
    assert live_cve.observed_packages(fps) == [("npm", "jquery", "3.4.1"),
                                               ("npm", "@popperjs/core", "2.11.8")]


def test_collect_end_to_end_and_fail_open(http, monkeypatch):
    calls, answers = http
    e = entry("CVE-2020-11023", kev=True)
    e["matched"] = {"ecosystem": "npm", "name": "jquery", "version": "3.4.1"}
    answers["/stack?"] = {"entries": [e]}
    answers["/api/v1/entries/"] = entry("CVE-2021-23017", cvss=7.7)
    fps = {"www.example.com": {"versions": [{"product": "jquery", "version": "3.4.1"},
                                            {"product": "nginx", "version": "1.18.0"}]}}
    out = live_cve.collect(fps)
    assert out["source"] == "cve.now" and out["complete"] is True
    assert out["packages"] == {"npm:jquery@3.4.1": ["CVE-2020-11023"]}
    assert "CVE-2020-11023" in out["cves"] and out["cves"]["CVE-2020-11023"]["kev"]
    assert not any("example.com" in c for c in calls)

    monkeypatch.setattr(live_cve, "_cache_path", lambda: "/nonexistent/dir/cache.json")
    answers.clear()
    answers["cve.now"] = RuntimeError("network down")
    broken = live_cve.collect(fps)
    assert broken["complete"] is False and broken["errors"] >= 1


# --------------------------------------------------------------------------
# read path
# --------------------------------------------------------------------------
LIVE = {
    "source": "cve.now", "fetched_at": "2026-10-23T05:00:00Z", "complete": True, "errors": 0,
    "packages": {"npm:jquery@3.4.1": ["CVE-2020-11022", "CVE-2020-11023"]},
    "cves": {
        "CVE-2020-11022": live_cve.compact(entry("CVE-2020-11022"), ("npm", "jquery", "3.4.1")),
        "CVE-2020-11023": live_cve.compact(entry("CVE-2020-11023", kev=True), ("npm", "jquery", "3.4.1")),
    },
}
META = {"date": "2026-10-23", "live_cves": LIVE, "fingerprints": {
    "www.example.com": {"url": "https://www.example.com", "code": "200",
                        "versions": [{"product": "jquery", "version": "3.4.1"}], "assets": []}}}


def test_live_ids_join_the_software_inventory():
    rows = cc.software_from_meta(META, [])
    jq = next(r for r in rows if r["product"] == "jquery")
    assert {"CVE-2020-11022", "CVE-2020-11023"} <= set(jq["related_cves"])


def test_live_cvss_overrides_the_curated_map():
    offline = cc._cve_severity_map()
    assert offline.get("CVE-2020-11022") == "HIGH"       # the vendored map's rating
    assert cc._cve_severity_map(META)["CVE-2020-11022"] == "MEDIUM"


def test_known_exploited_ranks_as_urgent_without_capping():
    result = cc.scorecard_from_snapshot(["example.com"], META, [])
    card = result["domains"][0]
    vuln = next(p for p in card["pillars"] if p["pillar"] == "vulnerability")
    item = vuln["deductions"][0]
    assert item["type"] == "vuln-kev" and "CVE-2020-11023" in item["detail"]
    assert item["points"] == sc._KEV_POINTS
    assert not card["critical_cap"]
    assert result["actions"][0]["type"] == "vuln-kev"
    assert result["actions"][0]["priority"] == "Urgent review"


def test_dependency_view_carries_live_detail():
    out = cc.dependencies_from_meta(META, ["example.com"])
    jq = next(p for p in out["packages"] if p["package"] == "jquery")
    assert jq["known_exploited"] == 1 and jq["upgrade_to"] == "3.5.0"
    first = jq["cves"][0]
    assert first["cve"] == "CVE-2020-11023" and first["kev"]["added"] == "2025-01-23"
    assert {c["source"] for c in jq["cves"]} >= {"cve.now"}
    assert out["summary"]["known_exploited"] == 1
    assert out["intel"]["live"]["advisories"] == 2


def test_cyclonedx_marks_kev_and_cvss_method(monkeypatch):
    monkeypatch.setattr(cc, "REGISTRY", {"acme": {"name": "Acme", "domains": ["example.com"]}})
    monkeypatch.setattr(cc, "_cached_org_data", lambda org: ([], None, None, META))
    monkeypatch.setattr(cc, "load_history", lambda org: [])
    bom = cc.dependencies_cyclonedx("acme")
    kev = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2020-11023")
    assert kev["ratings"][0]["method"] == "CVSSv31"
    assert kev["properties"][0]["name"] == "parallax:cisa-kev-added"


def test_no_live_intel_changes_nothing():
    meta = dict(META, live_cves=None)
    assert cc._known_exploited(meta) == set()
    assert cc.dependencies_from_meta(meta)["intel"]["live"] is None


# --------------------------------------------------------------------------
# refresh endpoint
# --------------------------------------------------------------------------
@pytest.fixture
def workspace(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"meta": {k: v for k, v in META.items() if k != "live_cves"},
                              "findings": []}))
    monkeypatch.setattr(cc, "REGISTRY", {"acme": {"name": "Acme", "domains": ["example.com"]}})
    monkeypatch.setattr(cc, "_org_paths", lambda slug: (str(fp), None))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    cc.invalidate_org_cache("acme")
    yield fp
    cc.invalidate_org_cache("acme")


def _client():
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


AUTH = {"X-CTI-Token": "test-tok"}


def test_refresh_requires_auth_and_opt_in(workspace, monkeypatch):
    monkeypatch.delenv("CTI_CVE_NOW", raising=False)
    c = _client()
    assert c.post("/api/orgs/acme/live-cves").status_code == 401
    r = c.post("/api/orgs/acme/live-cves", headers=AUTH)
    assert r.status_code == 403 and "CTI_CVE_NOW" in r.json()["hint"]


def test_refresh_writes_live_intel_for_the_current_snapshot(workspace, monkeypatch):
    monkeypatch.setenv("CTI_CVE_NOW", "1")
    monkeypatch.setattr(live_cve, "collect", lambda fps: dict(LIVE))
    r = _client().post("/api/orgs/acme/live-cves", headers=AUTH)
    assert r.status_code == 200 and r.json()["updated"] is True
    assert json.loads(workspace.read_text())["meta"]["live_cves"]["source"] == "cve.now"
    deps = _client().get("/api/dependencies", params={"org": "acme"}, headers=AUTH).json()
    assert deps["summary"]["known_exploited"] == 1


def test_refresh_never_attaches_intel_to_a_newer_snapshot(workspace, monkeypatch):
    monkeypatch.setenv("CTI_CVE_NOW", "1")

    def collect_while_a_scan_lands(fps):
        d = json.loads(workspace.read_text())
        d["meta"]["date"] = "2026-10-24"
        workspace.write_text(json.dumps(d))
        return dict(LIVE)
    monkeypatch.setattr(live_cve, "collect", collect_while_a_scan_lands)
    r = _client().post("/api/orgs/acme/live-cves", headers=AUTH).json()
    assert r["updated"] is False
    assert "live_cves" not in json.loads(workspace.read_text())["meta"]
