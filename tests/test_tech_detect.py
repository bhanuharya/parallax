"""Web-application framework / CMS detection with version extraction.

Pure string matching over already-captured evidence — no network. The bar
these tests enforce is the one that matters operationally: a version must be
extracted when it is genuinely present (so CVE matching can run), and an
identity-only detection must never be treated as versioned.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import tech_detect as td  # noqa: E402


def _by_product(dets):
    return {d["product"]: d for d in dets}


# --------------------------------------------------------------------------
# <meta generator> — the highest-value version source
# --------------------------------------------------------------------------
def test_wordpress_generator_version():
    d = _by_product(td.detect(html='<meta name="generator" content="WordPress 6.2.1">'))
    assert d["wordpress"]["version"] == "6.2.1"
    assert d["wordpress"]["source"] == "generator"
    assert d["wordpress"]["versioned"] is True
    assert d["wordpress"]["kind"] == "cms"


def test_drupal_generator_version():
    d = _by_product(td.detect(html='<meta content="Drupal 7.98" name="generator">'))
    assert d["drupal"]["version"] == "7.98"


def test_joomla_generator_version():
    d = _by_product(td.detect(html='<meta name="generator" content="Joomla! 3.4.5">'))
    assert d["joomla"]["version"] == "3.4.5"


def test_generator_can_be_passed_directly():
    d = _by_product(td.detect(generator="WordPress 5.9"))
    assert d["wordpress"]["version"] == "5.9"


def test_generator_identity_only_still_detected():
    d = _by_product(td.detect(html='<meta name="generator" content="Laravel">'))
    assert d["laravel"]["version"] == ""
    assert d["laravel"]["versioned"] is False
    assert d["laravel"]["confidence"] == td.CONF_IDENTITY


# --------------------------------------------------------------------------
# asset paths / framework attributes
# --------------------------------------------------------------------------
def test_jquery_asset_version():
    d = _by_product(td.detect(html='<script src="/js/jquery-3.6.0.min.js"></script>'))
    assert d["jquery"]["version"] == "3.6.0"
    assert d["jquery"]["kind"] == "js-library"


def test_bootstrap_css_version():
    d = _by_product(td.detect(html='<link href="/css/bootstrap-5.3.0.min.css">'))
    assert d["bootstrap"]["version"] == "5.3.0"
    assert d["bootstrap"]["kind"] == "css-framework"


def test_angular_ng_version_attribute():
    d = _by_product(td.detect(html='<app-root ng-version="17.0.0"></app-root>'))
    assert d["angular"]["version"] == "17.0.0"


def test_react_asset_version():
    d = _by_product(td.detect(html='<script src="/static/react-18.2.0.production.min.js">'))
    assert d["react"]["version"] == "18.2.0"


def test_nextjs_identity_only():
    d = _by_product(td.detect(html='<script src="/_next/static/chunks/main.js"></script>'))
    assert "next.js" in d
    assert d["next.js"]["version"] == ""


def test_framework_family_confidence():
    dets = td.detect(html='<script src="/js/jquery-3.6.0.min.js"></script>'
                          '<script src="/_next/static/x.js"></script>')
    d = _by_product(dets)
    assert d["jquery"]["confidence"] == td.CONF_VERSIONED
    assert d["next.js"]["confidence"] == td.CONF_IDENTITY


# --------------------------------------------------------------------------
# headers
# --------------------------------------------------------------------------
def test_aspnet_version_from_header():
    d = _by_product(td.detect(headers={"x-aspnet-version": "4.0.30319"}))
    assert d["asp.net"]["version"] == "4.0.30319"


def test_drupal_header_identity_only():
    d = _by_product(td.detect(headers={"x-drupal-cache": "HIT"}))
    assert "drupal" in d and d["drupal"]["version"] == ""


def test_jenkins_header_maps_to_jenkins_not_jira():
    d = _by_product(td.detect(headers={"x-jenkins": "2.401"}))
    assert "jenkins" in d and "jira" not in d


def test_edge_headers_detected():
    d = _by_product(td.detect(headers={"cf-ray": "abc", "x-varnish": "12345"}))
    assert d["cloudflare"]["kind"] == "edge"
    assert d["varnish"]["kind"] == "edge"


# --------------------------------------------------------------------------
# cookies
# --------------------------------------------------------------------------
def test_framework_from_session_cookie():
    d = _by_product(td.detect(cookies=["laravel_session=abc123; Path=/"]))
    assert d["laravel"]["source"] == "cookie"
    assert d["laravel"]["version"] == ""


def test_cookie_name_normalised_with_flags():
    # the scanner stores cookies as "name (flags)"
    d = _by_product(td.detect(cookies=["PHPSESSID (httponly,secure)"]))
    assert "php" in d


def test_django_csrf_cookie():
    d = _by_product(td.detect(cookies=["csrftoken (secure)"]))
    assert d["django"]["kind"] == "server-framework"


# --------------------------------------------------------------------------
# version hygiene
# --------------------------------------------------------------------------
def test_non_version_strings_rejected():
    # a captured group that is not purely numeric must not become a version
    assert td._clean_version("abc") == ""
    assert td._clean_version("") == ""
    assert td._clean_version("1.2.3") == "1.2.3"
    assert td._clean_version("0.0.30319") == "0.0.30319"


def test_overlong_version_rejected():
    assert td._clean_version("1" * 30) == ""


def test_version_upgrades_identity_detection():
    """A body signal gives identity; a generator later supplies the version.
    The result must be one row carrying the version, not two rows."""
    html = ('<meta name="generator" content="WordPress 6.2">'
            '<script src="/wp-includes/js/jquery-3.6.0.min.js"></script>')
    dets = td.detect(html=html)
    products = [d["product"] for d in dets]
    assert products.count("wordpress") == 1
    assert _by_product(dets)["wordpress"]["version"] == "6.2"


def test_no_duplicate_products():
    html = ('/wp-content/a.js /wp-content/b.js /wp-includes/c.js')
    dets = td.detect(html=html)
    assert [d["product"] for d in dets].count("wordpress") == 1


def test_sorting_versioned_first():
    dets = td.detect(html=('/_next/static/x.js'
                           '<script src="/js/jquery-3.6.0.min.js"></script>'))
    assert dets[0]["product"] == "jquery" and dets[0]["versioned"]
    assert dets[-1]["versioned"] is False


# --------------------------------------------------------------------------
# the contract that matters for CVE matching
# --------------------------------------------------------------------------
def test_as_versions_excludes_identity_only():
    dets = td.detect(html=('/_next/static/x.js'
                           '<script src="/js/jquery-3.6.0.min.js"></script>'))
    vers = td.as_versions(dets)
    assert {"product": "jquery", "version": "3.6.0"} in vers
    # next.js has no version and must not reach the CVE matcher
    assert not any(v["product"] == "next.js" for v in vers)


def test_versioned_helper():
    dets = td.detect(html='/wp-content/x.js<script src="/js/jquery-3.6.0.min.js"></script>')
    v = td.versioned(dets)
    assert all(d["version"] for d in v)
    assert {d["product"] for d in v} == {"jquery"}


def test_detect_never_raises_on_junk():
    assert td.detect() == []
    assert td.detect(html=None, headers=None, cookies=None) == []
    assert td.detect(html=123, headers="not-a-dict", cookies="abc") == []


def test_kind_mapping():
    assert td.kind_of("wordpress") == "cms"
    assert td.kind_of("WordPress") == "cms"
    assert td.kind_of("jquery") == "js-library"
    assert td.kind_of("django") == "server-framework"
    assert td.kind_of("shopify") == "ecommerce"
    assert td.kind_of("unknown-thing") == "other"


# --------------------------------------------------------------------------
# end-to-end: detection feeds CVE matching
# --------------------------------------------------------------------------
import cve_match  # noqa: E402


def test_detected_framework_versions_match_cves():
    """A WordPress 4.7.1 page must yield CVE matches, which is the entire
    point of extracting framework versions."""
    dets = td.detect(html='<meta name="generator" content="WordPress 4.7.1">')
    versions = td.as_versions(dets)
    hits = cve_match.match_cves(versions)
    assert any(h["cve"] == "CVE-2017-1001000" for h in hits)


def test_detected_jquery_version_matches_cves():
    dets = td.detect(html='<script src="/js/jquery-3.4.0.min.js"></script>')
    hits = cve_match.match_cves(td.as_versions(dets))
    assert any(h["cve"] == "CVE-2020-11022" for h in hits)


def test_fixed_framework_version_matches_nothing():
    dets = td.detect(html='<meta name="generator" content="WordPress 6.5">'
                          '<script src="/js/jquery-3.7.1.min.js"></script>')
    assert cve_match.match_cves(td.as_versions(dets)) == []


# --------------------------------------------------------------------------
# inventory surfacing
# --------------------------------------------------------------------------
import cti_correlation as cc  # noqa: E402
import scanner  # noqa: E402


# --------------------------------------------------------------------------
# curl response splitting (HTTP/1.1 CRLF vs HTTP/2 bare LF)
# --------------------------------------------------------------------------
def test_split_headers_body_http11_crlf():
    raw = "HTTP/1.1 200 OK\r\nserver: nginx\r\n\r\n<html>hi</html>"
    h, b = scanner._split_headers_body(raw)
    assert h.startswith("HTTP/1.1 200")
    assert b == "<html>hi</html>"


def test_split_headers_body_http2_bare_lf():
    """HTTP/2 responses separate headers with a bare LF. Splitting only on
    CRLF CRLF made the body empty for most of the modern web, silently
    disabling title/generator/tech/login detection."""
    raw = "HTTP/2 200 \nserver: nginx\ncontent-type: text/html\n\n<html>hi</html>"
    h, b = scanner._split_headers_body(raw)
    assert h.startswith("HTTP/2 200")
    assert b == "<html>hi</html>"


def test_split_headers_body_empty_input():
    assert scanner._split_headers_body("") == ("", "")
    assert scanner._split_headers_body(None) == ("", "")


def test_split_headers_body_no_body():
    raw = "HTTP/1.1 204 No Content\r\nserver: nginx\r\n\r\n"
    h, b = scanner._split_headers_body(raw)
    assert "204" in h and b == ""


def test_split_prefers_earliest_separator():
    raw = "HTTP/2 200 \na: b\n\nHTTP/1.1 200 OK\r\n\r\n"
    h, b = scanner._split_headers_body(raw)
    assert h == "HTTP/2 200 \na: b"
    assert b == "HTTP/1.1 200 OK\r\n\r\n"


def test_http2_body_reaches_detection():
    """The end-to-end consequence: an HTTP/2 response body must yield
    framework detections, not an empty result."""
    raw = ('HTTP/2 200 \nserver: nginx\n\n'
           '<meta name="generator" content="WordPress 6.2"><script src="/js/jquery-3.6.0.min.js"></script>')
    _, body = scanner._split_headers_body(raw)
    dets = td.detect(html=body)
    products = {d["product"]: d for d in dets}
    assert products["wordpress"]["version"] == "6.2"
    assert products["jquery"]["version"] == "3.6.0"


def test_inventory_shows_framework_rows():
    meta = {"fingerprints": {"blog.example.com": {
        "url": "https://blog.example.com",
        "versions": [{"product": "wordpress", "version": "4.7.1"}],
        "tech_detail": [{"product": "wordpress", "version": "4.7.1",
                         "kind": "cms", "confidence": "medium",
                         "source": "generator", "versioned": True}],
    }}}
    rows = cc.software_from_meta(meta, [])
    wp = [r for r in rows if r["product"] == "wordpress"][0]
    assert wp["kind"] == "cms"
    assert wp["detected_by"] == "generator"
    assert wp["cve_count"] >= 1


def test_inventory_shows_identity_only_detections():
    """A framework identified without a version is still inventory-worthy,
    but carries cve_count 0 because it cannot be matched."""
    meta = {"fingerprints": {"app.example.com": {
        "versions": [],
        "tech_detail": [{"product": "next.js", "version": "", "kind": "js-framework",
                         "confidence": "low", "source": "html", "versioned": False}],
    }}}
    rows = cc.software_from_meta(meta, [])
    assert len(rows) == 1
    assert rows[0]["product"] == "next.js"
    assert rows[0]["version"] == ""
    assert rows[0]["versioned"] is False
    assert rows[0]["cve_count"] == 0


def test_inventory_cves_attributed_per_product_not_per_host():
    """A host running WordPress + jQuery + Bootstrap must show each product's
    own CVEs. Matching the host's whole version list and showing that set on
    every row put the WordPress CVE on the Bootstrap row — misleading in a way
    that sends remediation to the wrong team."""
    versions = [{"product": "wordpress", "version": "4.7.1"},
                {"product": "jquery", "version": "3.4.0"},
                {"product": "bootstrap", "version": "4.3.0"}]
    meta = {"fingerprints": {"old.example.com": {"versions": versions}}}
    rows = {r["product"]: r for r in cc.software_from_meta(meta, [])}
    assert "CVE-2017-1001000" in rows["wordpress"]["related_cves"]
    assert "CVE-2019-8331" in rows["bootstrap"]["related_cves"]
    assert "CVE-2020-11022" in rows["jquery"]["related_cves"]
    # the WordPress-specific CVE must NOT appear on unrelated products
    assert "CVE-2017-1001000" not in rows["bootstrap"]["related_cves"]
    assert "CVE-2017-1001000" not in rows["jquery"]["related_cves"]
    assert rows["wordpress"]["cve_count"] == 2
    assert rows["bootstrap"]["cve_count"] == 1


def test_inventory_summary_counts_kinds():
    meta = {"fingerprints": {
        "a.example.com": {"versions": [{"product": "wordpress", "version": "4.7.1"}]},
        "b.example.com": {"versions": [{"product": "jquery", "version": "3.4.0"}]},
    }}
    s = cc.software_summary(cc.software_from_meta(meta, []))
    assert s["versioned"] == 2
    assert s["kinds"].get("cms") == 1
    assert s["kinds"].get("js-library") == 1
