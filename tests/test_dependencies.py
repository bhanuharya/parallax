"""Outside-in dependency inventory.

What these tests defend:

  - only explicit evidence names a package (CDN layouts, known library file
    names), and a floating CDN tag is never CVE-matched as an exact version;
  - query strings never reach storage (they can carry API keys);
  - first- vs third-party attribution respects the org's own domains;
  - "looked and found nothing" stays distinct from "never looked";
  - provider detection keeps verification tokens out of the output;
  - vulnerable packages carry the CVE detail and the version that fixes them.
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402
import dependencies as deps  # noqa: E402
import dns_posture  # noqa: E402
import scanner  # noqa: E402


# --------------------------------------------------------------------------
# library identification
# --------------------------------------------------------------------------
@pytest.mark.parametrize("url,expected", [
    ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js", ("jquery", "3.4.1", "cdnjs")),
    ("https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.7.9/angular.min.js", ("angularjs", "1.7.9", "cdnjs")),
    ("https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.2/js/bootstrap.min.js", ("bootstrap", "4.6.2", "cdnjs")),
    ("https://ajax.googleapis.com/ajax/libs/jquery/2.2.4/jquery.min.js", ("jquery", "2.2.4", "Google Hosted Libraries")),
    ("https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js", ("bootstrap", "5.3.2", "jsDelivr")),
    ("https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js", ("popper.js", "2.11.8", "jsDelivr")),
    ("https://cdn.jsdelivr.net/npm/vue@2/dist/vue.js", ("vue", "2", "jsDelivr")),
    ("https://cdn.jsdelivr.net/npm/lodash/lodash.min.js", ("lodash", None, "jsDelivr")),
    ("https://unpkg.com/react@18.2.0/umd/react.production.min.js", ("react", "18.2.0", "unpkg")),
    ("https://unpkg.com/angular@1.8.2/angular.js", ("angularjs", "1.8.2", "unpkg")),
    ("https://code.jquery.com/jquery-3.7.1.slim.min.js", ("jquery", "3.7.1", "jQuery CDN")),
    ("https://code.jquery.com/ui/1.13.2/jquery-ui.min.js", ("jquery-ui", "1.13.2", "jQuery CDN")),
    ("https://code.jquery.com/jquery-migrate-3.4.1.min.js", ("jquery-migrate", "3.4.1", "jQuery CDN")),
    ("https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css", ("bootstrap", "3.3.7", "BootstrapCDN")),
    ("https://www.example.com/js/jquery-1.12.4.min.js", ("jquery", "1.12.4", "file name")),
    ("https://www.example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", ("jquery", "3.7.1", "ver parameter")),
    ("https://www.example.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8",
     ("wp-plugin/contact-form-7", "5.8", "WordPress asset")),
    ("https://www.example.com/wp-content/themes/astra/assets/js/style.js",
     ("wp-theme/astra", None, "WordPress asset")),
])
def test_identify_known_layouts(url, expected):
    assert deps.identify(url) == expected


@pytest.mark.parametrize("url", [
    "https://www.example.com/static/app-2.1.0.min.js",     # unknown library name
    "https://www.example.com/js/chunk.3f9a1c.js",          # content hash, not a version
    "https://cdnjs.cloudflare.com/polyfill/v3/polyfill.min.js",
    "https://www.googletagmanager.com/gtag/js",
])
def test_identify_never_guesses(url):
    assert deps.identify(url) == (None, None, None)


# --------------------------------------------------------------------------
# asset extraction
# --------------------------------------------------------------------------
PAGE = """<html><head>
<link rel="icon" href="/favicon.ico">
<link rel="canonical" href="https://www.example.com/">
<link rel="stylesheet" href="http://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<link rel="modulepreload" href="/assets/index-4f2a.js">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"
        integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs"
        crossorigin="anonymous"></script>
<script src='//cdnjs.cloudflare.com/ajax/libs/angular.js/1.7.9/angular.min.js'></script>
<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyFAKEKEYFORTEST&amp;callback=init"></script>
<script src="https://cdn.example.com/js/site.js"></script>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="data:text/javascript,alert(1)"></script>
<script>inline()</script>
</head></html>"""


def _assets():
    return {a["url"]: a for a in deps.extract_assets(PAGE, "https://www.example.com")}


def test_extract_assets_scripts_styles_and_preloads_only():
    urls = set(_assets())
    assert "https://www.example.com/favicon.ico" not in urls
    assert "https://www.example.com/" not in urls
    assert "https://www.example.com/assets/index-4f2a.js" in urls
    assert not any(u.startswith("data:") for u in urls)
    # the duplicate jQuery tag is reported once
    assert sum(1 for u in urls if "jquery-3.7.1" in u) == 1


def test_extract_assets_drops_query_strings():
    """A Maps API key in the query string must never be stored."""
    joined = " ".join(_assets())
    assert "AIza" not in joined and "key=" not in joined
    assert "https://maps.googleapis.com/maps/api/js" in _assets()


def test_extract_assets_attributes():
    a = _assets()
    jq = a["https://code.jquery.com/jquery-3.7.1.min.js"]
    assert jq["sri"] is True and jq["third_party"] is True and jq["cdn"] == "jQuery CDN"
    ng = a["https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.7.9/angular.min.js"]
    assert ng["library"] == "angularjs" and ng["sri"] is False and ng["pinned"] is True
    bs = a["http://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"]
    assert bs["insecure"] is True and bs["kind"] == "style"
    # same registrable domain is first-party
    assert a["https://cdn.example.com/js/site.js"]["third_party"] is False


def test_extract_assets_respects_cap():
    html = "".join('<script src="/js/%d.js"></script>' % i for i in range(50))
    assert len(deps.extract_assets(html, "https://www.example.com", cap=10)) == 10


def test_site_of_handles_two_label_suffixes():
    assert deps.site_of("cdn.shop.example.co.uk") == "example.co.uk"
    assert deps.site_of("www.example.com") == "example.com"


# --------------------------------------------------------------------------
# risk rules
# --------------------------------------------------------------------------
def test_compromised_cdn_matches_subdomains_but_not_safe_mirrors():
    assert deps.compromised("cdn.polyfill.io")
    assert deps.compromised("polyfill.io")
    assert deps.compromised("cdn.bootcdn.net")
    assert deps.compromised("cdnjs.cloudflare.com") is None
    assert deps.compromised("notpolyfill.io") is None


@pytest.mark.parametrize("lib,version,eol", [
    ("angularjs", "1.8.3", True), ("jquery", "2.2.4", True), ("jquery", "3.7.1", False),
    ("bootstrap", "3.4.1", True), ("bootstrap", "4.6.2", True), ("bootstrap", "5.3.2", False),
    ("vue", "2.7.16", True), ("vue", "3.4.0", False), ("react", "16.0.0", False),
    ("jquery", None, False)])
def test_end_of_life_rules(lib, version, eol):
    assert bool(deps.end_of_life(lib, version)) is eol


def test_asset_issues_are_specific():
    a = _assets()
    assert deps.asset_issues(a["https://code.jquery.com/jquery-3.7.1.min.js"]) == {}
    ng = deps.asset_issues(a["https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.7.9/angular.min.js"])
    assert set(ng) == {"dep-eol", "dep-no-sri"}
    # SRI is expected on versioned public-CDN scripts, not on tag managers
    # or first-party bundles, and not on stylesheets
    assert "dep-no-sri" not in deps.asset_issues(a["https://maps.googleapis.com/maps/api/js"])
    assert "dep-no-sri" not in deps.asset_issues(a["https://cdn.example.com/js/site.js"])
    bs = deps.asset_issues(a["http://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"])
    assert set(bs) == {"dep-eol", "dep-mixed-content"}


def test_unpinned_only_for_floating_registries():
    floating = deps.extract_assets('<script src="https://unpkg.com/lodash"></script>',
                                   "https://www.example.com")[0]
    assert "dep-unpinned" in deps.asset_issues(floating)
    exact = deps.extract_assets(
        '<script src="https://unpkg.com/lodash@4.17.21/lodash.min.js" integrity="sha384-x"></script>',
        "https://www.example.com")[0]
    assert deps.asset_issues(exact) == {}


def test_as_versions_skips_floating_tags_and_wordpress_assets():
    html = ('<script src="https://cdn.jsdelivr.net/npm/vue@2/dist/vue.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>'
            '<script src="/wp-content/plugins/akismet/a.js?ver=5.3"></script>')
    versions = deps.as_versions(deps.extract_assets(html, "https://www.example.com"))
    assert versions == [{"product": "vue", "version": "2.6.14"}]


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------
RECORDS = {
    "mx": ["10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."],
    "ns": ["ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."],
    "txt": ['"v=spf1 include:_spf.google.com include:sendgrid.net ~all"',
            '"google-site-verification=SECRETTOKEN123"', '"MS=ms99887766"'],
    "cname_targets": [{"host": "shop.example.com", "cname": "shops.myshopify.com"},
                      {"host": "cdn.example.com", "cname": "d111111abcdef8.cloudfront.net"}],
}


def test_providers_from_records():
    rows = deps.providers_from_records("example.com", RECORDS)
    found = {(r["provider"], r["source"]) for r in rows}
    assert {("Google Workspace", "mx"), ("Cloudflare", "ns"), ("SendGrid", "spf"),
            ("Google", "txt"), ("Microsoft 365", "txt"), ("Shopify", "cname"),
            ("Amazon CloudFront", "cname")} <= found
    # one row per provider and source, however many records match
    assert sum(1 for r in rows if r["provider"] == "Google Workspace" and r["source"] == "mx") == 1


def test_provider_evidence_omits_verification_tokens():
    joined = str(deps.providers_from_records("example.com", RECORDS))
    assert "SECRETTOKEN123" not in joined and "99887766" not in joined


def test_providers_tolerate_failed_lookups():
    assert deps.providers_from_records("example.com", {"mx": None, "ns": None, "txt": None}) == []
    assert deps.providers_from_records("example.com", None) == []


def test_dns_gather_keeps_failed_provider_lookups_unknown(monkeypatch):
    def fake_query(name, rtype):
        return None if rtype in ("MX", "NS") else []
    monkeypatch.setattr(dns_posture, "_query", fake_query)
    snap = dns_posture.gather("example.com", hosts=[])
    assert snap["mx"] is None and snap["ns"] is None
    verdict = dns_posture.evaluate_domain("example.com", snap)
    assert verdict["records"]["mx"] is None


def test_dns_gather_records_all_cname_targets(monkeypatch):
    def fake_query(name, rtype):
        if rtype == "CNAME":
            return {"shop.example.com": ["shops.myshopify.com."]}.get(name, [])
        return []
    monkeypatch.setattr(dns_posture, "_query", fake_query)
    monkeypatch.setattr(dns_posture, "_resolve_target", lambda name: True)
    snap = dns_posture.gather("example.com", hosts=["shop.example.com", "www.example.com"])
    assert snap["cname_targets"] == [{"host": "shop.example.com", "cname": "shops.myshopify.com"}]


# --------------------------------------------------------------------------
# scanner integration
# --------------------------------------------------------------------------
def _fake_curl(raw):
    def run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=raw, stderr="")
    return run


def test_fingerprint_captures_assets_from_http2_body(monkeypatch):
    raw = ('HTTP/2 200 \nserver: nginx\n\n'
           '<html><script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js">'
           '</script></html>')
    monkeypatch.setattr(scanner.subprocess, "run", _fake_curl(raw))
    _, snippet = scanner._fetch_fingerprint("www.example.com")
    assert snippet["assets"][0]["library"] == "jquery"
    assert {"product": "jquery", "version": "3.4.1"} in snippet["versions"]


def test_fingerprint_without_document_has_no_assets_key(monkeypatch):
    """A redirect has no markup: absence of `assets` means not examined."""
    monkeypatch.setattr(scanner.subprocess, "run",
                        _fake_curl("HTTP/1.1 301 Moved\r\nlocation: /en/\r\n\r\n"))
    _, snippet = scanner._fetch_fingerprint("www.example.com")
    assert "assets" not in snippet


def test_assets_stay_out_of_finding_evidence():
    fs = [{"id": "F1", "target": "www.example.com", "evidence": {"assets": ["stale"]},
           "source": "scan-surface"}]
    snippets = {"www.example.com": {"url": "https://www.example.com", "code": "200",
                                    "assets": [{"url": "https://x"}]}}
    scanner._refresh_finding_evidence(fs, snippets, {})
    assert "assets" not in fs[0]["evidence"]
    assert fs[0]["evidence"]["code"] == "200"


# --------------------------------------------------------------------------
# read layer
# --------------------------------------------------------------------------
META = {
    "date": "2026-10-23",
    "fingerprints": {
        "www.example.com": {
            "url": "https://www.example.com", "code": "200", "server": "nginx/1.18.0",
            "versions": [{"product": "nginx", "version": "1.18.0"},
                         {"product": "jquery", "version": "3.4.1"}],
            "assets": deps.extract_assets(
                '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>'
                '<script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'
                '<script src="https://static.example-cdn.com/app.js"></script>',
                "https://www.example.com"),
        },
        "shop.example.com": {
            "url": "https://shop.example.com", "code": "200",
            "versions": [{"product": "jquery", "version": "3.4.1"},
                         {"product": "openresty", "version": "1.21.4.1"}],
            "assets": [],
        },
        "old.example.com": {"url": "https://old.example.com", "code": "200"},
    },
    "dns_posture": [{"domain": "example.com", "grade": "B", "score": 80, "checks": {},
                     "records": RECORDS}],
}


def test_packages_aggregate_across_hosts_with_cve_detail():
    out = cc.dependencies_from_meta(META, ["example.com", "example-cdn.com"])
    pkgs = {(p["package"], p["version"]): p for p in out["packages"]}
    jq = pkgs[("jquery", "3.4.1")]
    assert sorted(jq["hosts"]) == ["shop.example.com", "www.example.com"]
    assert jq["status"] == "vulnerable" and jq["cve_count"] >= 1
    assert jq["upgrade_to"] == "3.5.0"
    assert all({"cve", "severity", "fix_version"} <= set(c) for c in jq["cves"])
    # the asset URL is the evidence, not a vague "markup"
    assert any("cdnjs.cloudflare.com" in e["where"] for e in jq["evidence"])
    assert out["packages"][0]["status"] == "vulnerable"


def test_versions_are_never_masked_as_ip_addresses():
    out = cc.dependencies_from_meta(META, ["example.com"])
    assert ("openresty", "1.21.4.1") in {(p["package"], p["version"]) for p in out["packages"]}


def test_origins_respect_registered_domains_and_flag_compromise():
    out = cc.dependencies_from_meta(META, ["example.com", "example-cdn.com"])
    hosts = [o["host"] for o in out["origins"]]
    assert "static.example-cdn.com" not in hosts     # the org's own CDN domain
    assert hosts[0] == "cdn.polyfill.io" and out["origins"][0]["compromised"]
    assert out["summary"]["compromised"] == 1
    cdnjs = next(o for o in out["origins"] if o["host"] == "cdnjs.cloudflare.com")
    assert cdnjs["provider"] == "cdnjs" and cdnjs["with_sri"] == 0


def test_providers_merge_dns_and_script_sources():
    out = cc.dependencies_from_meta(META, ["example.com"])
    google = next(p for p in out["providers"] if p["provider"] == "Google Workspace")
    assert set(google["sources"]) == {"mx", "spf"}
    assert any(p["provider"] == "cdnjs" and p["sources"] == ["script"] for p in out["providers"])


def test_summary_counts():
    s = cc.dependencies_from_meta(META, ["example.com"])["summary"]
    assert s["pages"] == 2          # old.example.com was never examined
    assert s["vulnerable"] >= 2 and s["providers"] >= 5


def test_dependencies_endpoint_auth_and_shape():
    from fastapi.testclient import TestClient
    import main
    client = TestClient(main.app)
    assert client.get("/api/dependencies", params={"org": "sample"}).status_code == 401
    orgs = list(cc.REGISTRY.keys())
    if not orgs:
        pytest.skip("registry empty after earlier tests")
    r = client.get("/api/dependencies", params={"org": orgs[0]},
                   headers={"X-CTI-Token": "test-tok"})
    assert r.status_code == 200
    assert set(r.json()) >= {"summary", "packages", "origins", "providers"}


# --------------------------------------------------------------------------
# drift between scans
# --------------------------------------------------------------------------
def _snap(pages, origins=(), packages=()):
    return {"pages": sorted(pages), "origins": sorted(origins), "packages": sorted(packages)}


def _scan(snapshot, ts="t1"):
    return {"kind": "scan", "ts": ts, "dependencies": snapshot}


def test_new_origin_on_a_known_page_is_drift():
    old = _snap(["www.example.com"], ["www.example.com>cdnjs.cloudflare.com"])
    now = _snap(["www.example.com"], ["www.example.com>cdnjs.cloudflare.com",
                                      "www.example.com>cdn.polyfill.io"])
    ch = cc.dependency_changes(now, [_scan(old), _scan(now, "t2")])
    assert ch["baseline_at"] == "t1"
    assert [o["origin"] for o in ch["new_origins"]] == ["cdn.polyfill.io"]
    assert ch["new_origins"][0]["compromised"]


def test_first_look_and_failed_pages_are_not_drift():
    old = _snap(["a.example.com"], ["a.example.com>x.cdn.com"])
    # a.example.com failed to load this time; b.example.com is new
    now = _snap(["b.example.com"], ["b.example.com>y.cdn.com"])
    ch = cc.dependency_changes(now, [_scan(old)])
    assert ch["new_origins"] == [] and ch["removed_origins"] == []


def test_version_changes_are_reported_as_changes_not_add_and_remove():
    old = _snap(["www.example.com"], packages=["www.example.com>jquery@3.4.1"])
    now = _snap(["www.example.com"], packages=["www.example.com>jquery@3.7.1",
                                               "www.example.com>lodash@4.17.21"])
    ch = cc.dependency_changes(now, [_scan(old)])
    assert ch["version_changes"] == [{"page": "www.example.com", "package": "jquery",
                                      "from": ["3.4.1"], "to": "3.7.1"}]
    assert ch["new_packages"] == [{"page": "www.example.com", "package": "lodash",
                                   "version": "4.17.21"}]
    assert ch["removed_packages"] == []


def test_no_history_means_no_baseline():
    ch = cc.dependency_changes(_snap(["www.example.com"]), [])
    assert ch["baseline_at"] is None and ch["new_origins"] == []


def test_snapshot_records_examined_pages_only():
    snap = cc.dependency_snapshot(META, ["example.com"])
    assert snap["pages"] == ["shop.example.com", "www.example.com"]
    assert "www.example.com>cdn.polyfill.io" in snap["origins"]
    assert "www.example.com>jquery@3.4.1" in snap["packages"]


# --------------------------------------------------------------------------
# CycloneDX export
# --------------------------------------------------------------------------
def test_cyclonedx_export(monkeypatch):
    monkeypatch.setattr(cc, "REGISTRY", {"acme": {"name": "Acme", "domains": ["example.com"]}})
    monkeypatch.setattr(cc, "_cached_org_data", lambda org: ([], None, None, META))
    monkeypatch.setattr(cc, "load_history", lambda org: [])
    bom = cc.dependencies_cyclonedx("acme")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["compositions"][0]["aggregate"] == "incomplete"
    jq = next(c for c in bom["components"] if c["name"] == "jquery")
    assert jq["purl"] == "pkg:npm/jquery@3.4.1"
    refs = {c["bom-ref"] for c in bom["components"]}
    for v in bom["vulnerabilities"]:
        assert v["id"].startswith("CVE-") and v["affects"]
        assert {a["ref"] for a in v["affects"]} <= refs
    assert any(v.get("recommendation") == "Upgrade to 3.5.0 or later." for v in bom["vulnerabilities"])


def test_cyclonedx_endpoint_requires_auth():
    from fastapi.testclient import TestClient
    import main
    r = TestClient(main.app).get("/api/dependencies/cyclonedx", params={"org": "sample"})
    assert r.status_code == 401
