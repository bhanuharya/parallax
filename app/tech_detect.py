"""tech_detect.py — web-application framework and CMS detection with versions.

The passive scanner already parses product/version tokens out of `Server` and
`X-Powered-By` headers. That finds web *servers*; it misses the application
stack, which is where most exploitable CVEs actually live. A WordPress site
behind nginx discloses "nginx/1.18.0" and nothing about WordPress itself.

This module closes that gap using only evidence a normal visitor receives:

  generator  The <meta name="generator"> tag — the single most reliable
             version source for CMSs (`WordPress 6.2`, `Drupal 7.98`).
  assets     Version-bearing script/CSS paths and attributes
             (`jquery-3.6.0.min.js`, `ng-version="17.0.0"`, `?ver=6.2`).
  headers    `X-AspNet-Version`, `X-Drupal-Cache`, `X-Generator`, ...
  cookies    Session cookie names identify the framework even when it
             discloses no version (`laravel_session`, `ci_session`,
             `csrftoken`, `_rails_session`).

Design notes:
  - Pure functions: no I/O, no network. Everything here is string matching on
    data the scanner already captured, so it is fully unit-testable.
  - Versioned detections are labelled `medium` confidence; identity-only (no
    version) detections are `low` and are NEVER fed to CVE matching — a
    product name without a version cannot be matched to an affected range.
  - Conservative by construction: a signature only matches when its evidence
    is specific. Guessing produces the false positives that make fingerprint
    scanners untrustworthy (e.g. the bare word "drupal" appearing in copy).
"""
import re

# Detections without a version are still useful for the inventory, but they
# are reported as identity-only and must not drive CVE matching.
CONF_VERSIONED = "medium"
CONF_IDENTITY = "low"

# --- <meta name="generator"> ------------------------------------------------
# (product, pattern, version-group-index; 0 = identity only)
_GENERATOR_SIGS = (
    ("wordpress", re.compile(r"WordPress\s+([\d.]+)", re.I), 1),
    ("drupal", re.compile(r"Drupal\s+([\d.]+)", re.I), 1),
    ("joomla", re.compile(r"Joomla!?(?:\s+v?([\d.]+))?", re.I), 1),
    ("hugo", re.compile(r"Hugo\s+([\d.]+)", re.I), 1),
    ("jekyll", re.compile(r"Jekyll\s+v?([\d.]+)", re.I), 1),
    ("ghost", re.compile(r"Ghost\s+([\d.]+)", re.I), 1),
    ("typo3", re.compile(r"TYPO3\s+CMS\s+([\d.]+)", re.I), 1),
    ("mediawiki", re.compile(r"MediaWiki\s+([\d.]+)", re.I), 1),
    ("moodle", re.compile(r"Moodle\s+([\d.]+)", re.I), 1),
    ("prestashop", re.compile(r"PrestaShop\s+([\d.]+)", re.I), 1),
    ("opencart", re.compile(r"OpenCart", re.I), 0),
    ("wix", re.compile(r"Wix\.com", re.I), 0),
    ("squarespace", re.compile(r"Squarespace", re.I), 0),
    ("webflow", re.compile(r"Webflow", re.I), 0),
    ("django", re.compile(r"Django\s+([\d.]+)", re.I), 1),
    ("laravel", re.compile(r"Laravel", re.I), 0),
    ("next.js", re.compile(r"Next\.js\s+([\d.]+)", re.I), 1),
)

# --- HTML body: asset paths, framework attributes ---------------------------
# Version-bearing signatures run first so a host reports the precise version
# rather than only the family label.
_HTML_SIGS = (
    ("jquery", re.compile(r"jquery[-.]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I), 1),
    ("bootstrap", re.compile(r"bootstrap[.-]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)", re.I), 1),
    ("angular", re.compile(r"ng-version=[\"']([\d.]+)[\"']", re.I), 1),
    ("angularjs", re.compile(r"angular(?:js)?[.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), 1),
    ("react", re.compile(r"react(?:-dom)?[.-]v?(\d+\.\d+\.\d+)"
                         r"(?:\.min|\.production(?:\.min)?)?\.js", re.I), 1),
    ("vue", re.compile(r"vue(?:\.runtime)?[.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), 1),
    ("moment.js", re.compile(r"moment[.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), 1),
    ("lodash", re.compile(r"lodash[.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), 1),
    ("d3", re.compile(r"d3[.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), 1),

    # identity-only families (no reliable version in the markup)
    ("next.js", re.compile(r"/_next/static/|__NEXT_DATA__", re.I), 0),
    ("nuxt", re.compile(r"/_nuxt/|__NUXT__", re.I), 0),
    ("sveltekit", re.compile(r"__sveltekit|/_app/immutable/", re.I), 0),
    ("remix", re.compile(r"__remixContext", re.I), 0),
    ("gatsby", re.compile(r"___gatsby|gatsby-plugin", re.I), 0),
    ("astro", re.compile(r"data-astro-|/_astro/", re.I), 0),
    ("wordpress", re.compile(r"/wp-content/|/wp-includes/|/wp-json/", re.I), 0),
    ("drupal", re.compile(r"/sites/default/files/|Drupal\.settings|drupalSettings", re.I), 0),
    ("joomla", re.compile(r"/media/system/js/|/components/com_", re.I), 0),
    ("magento", re.compile(r"/static/version\d+/frontend/|Magento_|mage/cookies", re.I), 0),
    ("shopify", re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I), 0),
    ("django", re.compile(r"csrfmiddlewaretoken", re.I), 0),
    ("rails", re.compile(r"authenticity_token|csrf-token[\"']?\s+content=", re.I), 0),
    ("asp.net", re.compile(r"__VIEWSTATE|__EVENTVALIDATION", re.I), 0),
    ("sharepoint", re.compile(r"_spPageContextInfo|_layouts/15/", re.I), 0),
    ("confluence", re.compile(r"ajs-version-number|confluence", re.I), 0),
    ("jira", re.compile(r"ajs-version-number|jira", re.I), 0),
)

# --- response headers -------------------------------------------------------
# (product, header-name, pattern, version-group; header value is the subject)
_HEADER_SIGS = (
    ("asp.net", "x-aspnet-version", re.compile(r"(\d+\.\d+(?:\.\d+)?)"), 1),
    ("asp.net", "x-aspnetmvc-version", re.compile(r"(\d+\.\d+(?:\.\d+)?)"), 1),
    ("drupal", "x-drupal-cache", re.compile(r"."), 0),
    ("drupal", "x-drupal-dynamic-cache", re.compile(r"."), 0),
    ("jira", "x-jira-meta", re.compile(r"."), 0),
    ("jenkins", "x-jenkins", re.compile(r"."), 0),
    ("jenkins", "x-jenkins-session", re.compile(r"."), 0),
    ("gitlab", "x-gitlab-meta", re.compile(r"."), 0),
    ("next.js", "x-nextjs-cache", re.compile(r"."), 0),
    ("next.js", "x-nextjs-prerender", re.compile(r"."), 0),
    ("shopify", "x-shopify-stage", re.compile(r"."), 0),
    ("cloudflare", "cf-ray", re.compile(r"."), 0),
    ("varnish", "x-varnish", re.compile(r"."), 0),
    ("akamai", "x-akamai-transformed", re.compile(r"."), 0),
)

# --- cookies ----------------------------------------------------------------
# Cookie names are a strong identity signal even when no version is exposed.
# Lowercased name -> product. Values are deliberately ignored (PII).
_COOKIE_SIGS = {
    "phpsessid": "php",
    "asp.net_sessionid": "asp.net",
    "aspsessionid": "asp.net",
    "laravel_session": "laravel",
    "ci_session": "codeigniter",
    "cakephp": "cakephp",
    "_rails_session": "rails",
    "_session_id": "rails",
    "csrftoken": "django",
    "wordpress_test_cookie": "wordpress",
    "wp-settings-": "wordpress",
    "frontend_lang": "magento",
    "adminhtml": "magento",
    "jsessionid": "java",
    "drupal": "drupal",
    "squiz_matrix": "squiz matrix",
}

# Product -> coarse kind, for inventory grouping and UI labelling.
_KINDS = {
    "wordpress": "cms", "drupal": "cms", "joomla": "cms", "typo3": "cms",
    "moodle": "cms", "mediawiki": "cms", "ghost": "cms", "hugo": "ssg",
    "jekyll": "ssg", "gatsby": "ssg", "astro": "ssg", "prestashop": "ecommerce",
    "opencart": "ecommerce", "magento": "ecommerce", "shopify": "ecommerce",
    "wix": "website-builder", "squarespace": "website-builder",
    "webflow": "website-builder",
    "jquery": "js-library", "bootstrap": "css-framework", "moment.js": "js-library",
    "lodash": "js-library", "d3": "js-library",
    "react": "js-framework", "vue": "js-framework", "angular": "js-framework",
    "angularjs": "js-framework", "next.js": "js-framework", "nuxt": "js-framework",
    "sveltekit": "js-framework", "remix": "js-framework",
    "django": "server-framework", "rails": "server-framework",
    "laravel": "server-framework", "asp.net": "server-framework",
    "codeigniter": "server-framework", "cakephp": "server-framework",
    "php": "language-runtime", "java": "language-runtime",
    "confluence": "appliance", "jira": "appliance", "sharepoint": "appliance",
    "cloudflare": "edge", "varnish": "edge", "akamai": "edge",
}

_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")
_MAX_VERSION_LEN = 20
_GENERATOR_TAG_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)[\"']", re.I)
_GENERATOR_TAG_RE_ALT = re.compile(
    r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]*name=[\"']generator[\"']", re.I)


def kind_of(product):
    """Coarse category for a detected product (or 'other')."""
    return _KINDS.get(str(product or "").strip().lower(), "other")


def _clean_version(value):
    """Normalise a captured version string, or '' when it is not a version."""
    v = str(value or "").strip().strip(".")
    if not v or len(v) > _MAX_VERSION_LEN:
        return ""
    return v if _VERSION_RE.match(v) else ""


def _add(out, seen, product, version, source, evidence):
    """Record one detection, keeping the best (versioned) evidence per product."""
    product = str(product or "").strip().lower()
    if not product:
        return
    version = _clean_version(version) if version else ""
    idx = seen.get(product)
    if idx is not None:
        # upgrade identity-only to versioned in place; never downgrade
        prev = out[idx]
        if prev.get("version") or not version:
            return
        out[idx] = _detection(product, version, source, evidence)
        return
    seen[product] = len(out)
    out.append(_detection(product, version, source, evidence))


def _detection(product, version, source, evidence):
    return {
        "product": product,
        "version": version,
        "kind": kind_of(product),
        "confidence": CONF_VERSIONED if version else CONF_IDENTITY,
        "source": source,
        "evidence": str(evidence or "")[:120],
        "versioned": bool(version),
    }


def _cookie_name(entry):
    """Cookie entries arrive as 'name (flags)' or 'name' — take the name."""
    return str(entry or "").split(" ", 1)[0].strip().lower().rstrip("=")


def detect(html="", headers=None, generator="", cookies=None):
    """Detect frameworks/CMSs from already-captured evidence.

    `headers` is a mapping of lowercase header name -> value (the scanner's
    snippet dict qualifies). `cookies` is a list of cookie-name strings.
    Returns a list of detection dicts, versioned first, then by product:
        {product, version, kind, confidence, source, evidence, versioned}
    """
    out = []
    seen = {}

    # 1. <meta generator> — highest-value source for CMS versions. The caller
    # may pass the tag value, but it is also recovered from the body so this
    # module stays self-sufficient when only HTML is available.
    gen = str(generator or "").strip() if isinstance(generator, str) else ""
    body = html if isinstance(html, str) else ""
    if not gen and body:
        m = _GENERATOR_TAG_RE.search(body) or _GENERATOR_TAG_RE_ALT.search(body)
        if m:
            gen = m.group(1).strip()[:80]
    if gen:
        for product, rx, vgroup in _GENERATOR_SIGS:
            m = rx.search(gen)
            if not m:
                continue
            version = m.group(vgroup) if vgroup else ""
            _add(out, seen, product, version, "generator", gen)
            break  # one generator tag describes one product

    # 2. response headers
    hdrs = headers or {}
    if isinstance(hdrs, dict):
        for product, header, rx, vgroup in _HEADER_SIGS:
            raw = hdrs.get(header)
            if not raw:
                continue
            m = rx.search(str(raw))
            if not m:
                continue
            version = m.group(vgroup) if vgroup else ""
            _add(out, seen, product, version, "header", "%s: %s" % (header, raw))

    # 3. HTML body (assets + framework attributes)
    if body:
        for product, rx, vgroup in _HTML_SIGS:
            m = rx.search(body)
            if not m:
                continue
            version = m.group(vgroup) if vgroup else ""
            _add(out, seen, product, version, "html", m.group(0))

    # 4. cookies (identity only — values are never read)
    for entry in (cookies or []):
        name = _cookie_name(entry)
        if not name:
            continue
        for sig, product in _COOKIE_SIGS.items():
            if name == sig or name.startswith(sig):
                _add(out, seen, product, "", "cookie", "cookie: %s" % name)
                break

    out.sort(key=lambda d: (0 if d["versioned"] else 1, d["product"]))
    return out


def versioned(detections):
    """Only the detections carrying a version — the safe input for CVE matching."""
    return [d for d in (detections or []) if d.get("version")]


def as_versions(detections, cap=8):
    """Convert versioned detections to the scanner's [{product, version}] shape."""
    out = []
    for d in versioned(detections)[:cap]:
        pv = {"product": d["product"], "version": d["version"]}
        if pv not in out:
            out.append(pv)
    return out
