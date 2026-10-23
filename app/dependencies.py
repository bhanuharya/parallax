"""dependencies.py — outside-in software supply-chain inventory.

Much of what a site depends on is visible to any visitor: the scripts and
stylesheets its pages load, who hosts them, and the service providers its DNS
points at. This module reads that from evidence the scan already captured —
the homepage markup (first FINGERPRINT_BODY_BYTES) and the DNS records
gathered for posture. It never fetches the assets themselves.

  assets      every <script src> and stylesheet/preload <link href>: origin,
              first or third party, Subresource Integrity, plaintext loads
  libraries   library + version from well-known CDN and file-name layouts
              (cdnjs, jsDelivr, unpkg, Google Hosted Libraries, code.jquery.com,
              `name-1.2.3.min.js`, WordPress `?ver=` assets)
  risk        compromised CDN hosts, end-of-life libraries, mixed content,
              unpinned CDN versions and CDN assets without integrity hashes
  providers   third-party services a domain relies on, from MX, NS, SPF
              includes, verification TXT records, CNAME targets and script hosts

Design notes, following tech_detect.py:
  - Pure functions: no I/O. Rule tables (EOL, compromised hosts, providers)
    are applied at read time, so updating a table re-evaluates old scans.
  - Conservative: a library is only named from an explicit CDN layout or a
    known library file name. A bare `app-2.1.js` is not a dependency claim.
  - Query strings are dropped before storage (they can carry API keys); only
    a `ver=` value is kept.
"""
import html as _html
import re
from urllib.parse import parse_qs, urljoin, urlsplit

ASSET_URL_CAP = 200

# Compromised CDN hosts: anything loaded from these executes code chosen by
# whoever controls the domain today.
COMPROMISED_HOSTS = {
    "polyfill.io": "polyfill.io changed hands in 2024 and served malicious "
                   "code to sites that embedded it.",
    "bootcdn.net": "Linked by researchers to the operator behind the 2024 "
                   "polyfill.io compromise.",
    "bootcss.com": "Linked by researchers to the operator behind the 2024 "
                   "polyfill.io compromise.",
    "staticfile.net": "Linked by researchers to the operator behind the 2024 "
                      "polyfill.io compromise.",
    "staticfile.org": "Linked by researchers to the operator behind the 2024 "
                      "polyfill.io compromise.",
}

# Public CDNs serving immutable, versioned files — where pinning a version and
# an integrity hash is both possible and expected.
PUBLIC_CDNS = {
    "cdnjs.cloudflare.com": "cdnjs",
    "ajax.googleapis.com": "Google Hosted Libraries",
    "cdn.jsdelivr.net": "jsDelivr",
    "fastly.jsdelivr.net": "jsDelivr",
    "gcore.jsdelivr.net": "jsDelivr",
    "unpkg.com": "unpkg",
    "code.jquery.com": "jQuery CDN",
    "stackpath.bootstrapcdn.com": "BootstrapCDN",
    "maxcdn.bootstrapcdn.com": "BootstrapCDN",
    "netdna.bootstrapcdn.com": "BootstrapCDN",
    "ajax.aspnetcdn.com": "Microsoft Ajax CDN",
}

# Canonical library names. Kept aligned with tech_detect so a library seen by
# both produces one software row, not two.
_ALIASES = {
    "angular.js": "angularjs", "twitter-bootstrap": "bootstrap",
    "jqueryui": "jquery-ui", "jquery.ui": "jquery-ui", "moment": "moment.js",
    "lodash.js": "lodash", "underscore.js": "underscore",
    "backbone.js": "backbone", "handlebars.js": "handlebars",
    "react-dom": "react", "vue.js": "vue", "@popperjs/core": "popper.js",
    "@fortawesome/fontawesome-free": "font-awesome",
    "jquery.min": "jquery", "jquery.slim": "jquery",
}
# Canonical library name -> package name on npm: used for package URLs in the
# CycloneDX export and for live advisory lookups (live_cve.py).
NPM_NAMES = {
    "jquery": "jquery", "jquery-ui": "jquery-ui", "jquery-migrate": "jquery-migrate",
    "bootstrap": "bootstrap", "angularjs": "angular", "react": "react", "vue": "vue",
    "moment.js": "moment", "lodash": "lodash", "underscore": "underscore",
    "backbone": "backbone", "handlebars": "handlebars", "d3": "d3",
    "popper.js": "@popperjs/core", "dompurify": "dompurify", "select2": "select2",
    "swiper": "swiper", "font-awesome": "@fortawesome/fontawesome-free",
}
# Names accepted from a bare file name (`jquery-3.4.1.min.js`). CDN layouts
# name their package explicitly and do not need this list.
_KNOWN_LIBS = {
    "jquery", "jquery-ui", "jquery-migrate", "jquery-mobile", "bootstrap",
    "angularjs", "react", "vue", "moment.js", "lodash", "underscore",
    "backbone", "handlebars", "knockout", "ember", "d3", "select2",
    "modernizr", "popper.js", "swiper", "dompurify", "font-awesome",
}

_TAG_RE = re.compile(r"<(script|link)\b([^>]*)>", re.I)
_ATTR_RE = re.compile(
    r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?""")
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.]+)?)$")
_PINNED_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$")
_FILE_RE = re.compile(
    r"([a-z][a-z0-9.-]*?)[-.@]v?(\d+\.\d+(?:\.\d+)?)"
    r"(?:\.(?:min|slim|bundle|umd|production|prod|esm))*\.(?:js|css)$", re.I)
_CDN_LAYOUTS = (
    (re.compile(r"^(?:cdnjs\.cloudflare\.com|ajax\.googleapis\.com)$"),
     re.compile(r"^/ajax/libs/([^/]+)/([^/]+)/")),
    (re.compile(r"^(?:cdn|fastly|gcore)\.jsdelivr\.net$"),
     re.compile(r"^/npm/((?:@[^/@]+/)?[^/@]+)(?:@([^/]+))?")),
    (re.compile(r"^unpkg\.com$"),
     re.compile(r"^/((?:@[^/@]+/)?[^/@]+)(?:@([^/]+))?")),
    (re.compile(r"^(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com$"),
     re.compile(r"^/(bootstrap|font-awesome|bootswatch)/([^/]+)/")),
)
_JQUERY_CDN = (
    (re.compile(r"^/ui/([\d.]+)/"), "jquery-ui"),
    (re.compile(r"^/mobile/([\d.]+)/"), "jquery-mobile"),
    (re.compile(r"^/jquery-migrate-([\d.]+?)(?:\.min)?\.js$"), "jquery-migrate"),
    (re.compile(r"^/jquery-([\d.]+?)(?:\.slim)?(?:\.min)?\.js$"), "jquery"),
)
_WP_ASSET_RE = re.compile(r"/wp-content/(plugins|themes)/([a-z0-9_-]+)/", re.I)

# Two-label public suffixes common enough to matter for first/third-party
# attribution without shipping the full Public Suffix List.
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr", "com.br", "com.cn",
    "com.tw", "com.hk", "com.sg", "co.in", "co.nz", "co.za", "com.mx",
    "com.tr", "co.id", "com.my", "com.vn",
}


def site_of(host):
    """Registrable domain approximation: `a.b.example.co.uk` -> `example.co.uk`."""
    labels = str(host or "").strip().lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_matches(host, domain):
    host = str(host or "").lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def compromised(host):
    """Why loading from `host` is unsafe, or None."""
    for domain, why in COMPROMISED_HOSTS.items():
        if _host_matches(host, domain):
            return why
    return None


def _canonical(name, version=None):
    name = str(name or "").strip().lower()
    if name == "angular" and str(version or "").startswith("1."):
        return "angularjs"   # npm "angular" is AngularJS; Angular 2+ is @angular/*
    return _ALIASES.get(name, name)


def _clean_version(value):
    m = _VERSION_RE.match(str(value or "").strip())
    return m.group(1) if m else None


def identify(url):
    """(library, version, source) for an asset URL, or (None, None, None).

    `version` is None when the library is identified but its version is not
    (a floating CDN tag such as @latest, or a WordPress asset without ver=).
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    ver_param = _clean_version((parse_qs(parts.query).get("ver") or [""])[0])
    for host_re, path_re in _CDN_LAYOUTS:
        if host_re.match(host):
            m = path_re.match(path)
            if m:
                version = _clean_version(m.group(2)) if m.group(2) else None
                return _canonical(m.group(1), version), version, PUBLIC_CDNS.get(host, host)
            return None, None, None
    if host == "code.jquery.com":
        for path_re, name in _JQUERY_CDN:
            m = path_re.match(path)
            if m:
                return name, _clean_version(m.group(1)), "jQuery CDN"
        return None, None, None
    base = path.rsplit("/", 1)[-1]
    m = _FILE_RE.search(base)
    if m:
        name = _canonical(m.group(1), m.group(2))
        if name in _KNOWN_LIBS:
            return name, _clean_version(m.group(2)), "file name"
    # WordPress enqueues core-bundled libraries with ver=<library version>
    stem = re.sub(r"(?:\.min)?\.(?:js|css)$", "", base.lower())
    name = _canonical(stem)
    if name in _KNOWN_LIBS and ver_param:
        return name, ver_param, "ver parameter"
    wp = _WP_ASSET_RE.search(path)
    if wp:
        kind = "wp-plugin" if wp.group(1).lower() == "plugins" else "wp-theme"
        return "%s/%s" % (kind, wp.group(2).lower()), ver_param, "WordPress asset"
    return None, None, None


def _attrs(blob):
    out = {}
    for m in _ATTR_RE.finditer(blob or ""):
        key = m.group(1).lower()
        if key not in out:
            val = next((g for g in m.group(2, 3, 4) if g is not None), "")
            out[key] = _html.unescape(val).strip()
    return out


def extract_assets(html, page_url, cap=30):
    """Scripts and stylesheets referenced by a page, as compact asset rows.

    Each row: {url, host, kind, sri, insecure, third_party, library, version,
    pinned, cdn}. Duplicate URLs are reported once. `url` has its query
    string and fragment removed.
    """
    page = urlsplit(str(page_url or ""))
    page_host = (page.hostname or "").lower()
    page_https = page.scheme == "https"
    out, seen = [], set()
    for m in _TAG_RE.finditer(html or ""):
        tag = m.group(1).lower()
        a = _attrs(m.group(2))
        if tag == "script":
            ref, kind = a.get("src"), "script"
        else:
            rel = set(a.get("rel", "").lower().split())
            if "stylesheet" in rel:
                kind = "style"
            elif "modulepreload" in rel or ("preload" in rel and a.get("as", "").lower() == "script"):
                kind = "script"
            else:
                continue
            ref = a.get("href")
        if not ref or ref.lower().startswith(("data:", "blob:", "javascript:")):
            continue
        absolute = urljoin(page_url.rstrip("/") + "/", ref)
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        host = parts.hostname.lower()
        clean = ("%s://%s%s" % (parts.scheme, parts.netloc.lower(), parts.path))[:ASSET_URL_CAP]
        if clean in seen:
            continue
        seen.add(clean)
        library, version, source = identify(absolute)
        out.append({
            "url": clean, "host": host, "kind": kind,
            "sri": a.get("integrity", "").lower().startswith(("sha256-", "sha384-", "sha512-")),
            "insecure": page_https and parts.scheme == "http",
            "third_party": host != page_host and site_of(host) != site_of(page_host),
            "library": library, "version": version,
            "pinned": bool(version and _PINNED_RE.match(version)),
            "cdn": PUBLIC_CDNS.get(host),
            "source": source,
        })
        if len(out) >= cap:
            break
    return out


def as_versions(assets, cap=8):
    """Versioned libraries in the scanner's [{product, version}] shape, so the
    existing CVE matcher and software inventory cover them."""
    out = []
    for a in assets or ():
        # a floating CDN tag (vue@2) names a range, not the version served
        floating = a.get("source") in ("jsDelivr", "unpkg") and not a.get("pinned")
        if a.get("library") and a.get("version") and not floating \
                and not str(a["library"]).startswith("wp-"):
            pv = {"product": a["library"], "version": a["version"]}
            if pv not in out:
                out.append(pv)
        if len(out) >= cap:
            break
    return out


# --------------------------------------------------------------------------
# lifecycle
# --------------------------------------------------------------------------
def _major(version):
    try:
        return int(str(version).split(".")[0])
    except (TypeError, ValueError):
        return None


def end_of_life(library, version):
    """Why this library line no longer receives security fixes, or None."""
    major = _major(version)
    if major is None:
        return None
    if library == "angularjs" and major == 1:
        return "AngularJS reached end of life on 31 December 2021."
    if library == "jquery" and major < 3:
        return "jQuery 1.x and 2.x no longer receive security fixes."
    if library == "bootstrap" and major <= 3:
        return "Bootstrap 3 and earlier are end of life (Bootstrap 3 since 24 July 2019)."
    if library == "bootstrap" and major == 4:
        return "Bootstrap 4 reached end of life on 1 January 2023."
    if library == "vue" and major == 2:
        return "Vue 2 reached end of life on 31 December 2023."
    return None


def asset_issues(asset):
    """Issue types one asset raises: {type: descriptor}."""
    label = asset.get("library") or asset.get("host") or ""
    if asset.get("version"):
        label = "%s %s" % (label, asset["version"])
    out = {}
    if compromised(asset.get("host")):
        out["dep-compromised"] = asset.get("host")
    if asset.get("library") and end_of_life(asset["library"], asset.get("version")):
        out["dep-eol"] = label
    if asset.get("insecure"):
        out["dep-mixed-content"] = asset.get("host")
    if asset.get("cdn") and asset.get("kind") == "script" and not asset.get("sri"):
        out["dep-no-sri"] = label
    if asset.get("cdn") and asset.get("library") and not asset.get("pinned") \
            and asset.get("source") in ("jsDelivr", "unpkg"):
        out["dep-unpinned"] = label
    return out


# --------------------------------------------------------------------------
# service providers
# --------------------------------------------------------------------------
# (source, provider, category, pattern). Patterns run against lowercased
# record values; MX/NS/CNAME values are hostnames without the trailing dot.
_PROVIDERS = (
    ("mx", "Google Workspace", "Email", r"(^|\.)(google|googlemail)\.com$"),
    ("mx", "Microsoft 365", "Email", r"\.mail\.protection\.outlook\.com$"),
    ("mx", "Proofpoint", "Email security", r"\.(pphosted|ppe-hosted)\.com$"),
    ("mx", "Mimecast", "Email security", r"\.mimecast\.com$"),
    ("mx", "Barracuda", "Email security", r"\.barracudanetworks\.com$"),
    ("mx", "Cisco Secure Email", "Email security", r"\.iphmx\.com$"),
    ("mx", "Zoho Mail", "Email", r"\.zoho\.(com|eu|in)$"),
    ("mx", "Amazon WorkMail / SES", "Email", r"\.amazonaws\.com$"),
    ("ns", "Cloudflare", "DNS hosting", r"\.ns\.cloudflare\.com$"),
    ("ns", "Amazon Route 53", "DNS hosting", r"^ns-\d+\.awsdns-\d+\."),
    ("ns", "Azure DNS", "DNS hosting", r"\.azure-dns\.(com|net|org|info)$"),
    ("ns", "Google Cloud DNS", "DNS hosting", r"\.googledomains\.com$"),
    ("ns", "GoDaddy", "DNS hosting", r"\.domaincontrol\.com$"),
    ("ns", "Akamai", "DNS hosting", r"\.akam\.net$"),
    ("ns", "NS1", "DNS hosting", r"\.nsone\.net$"),
    ("ns", "DNSimple", "DNS hosting", r"\.dnsimple\.com$"),
    ("spf", "Google Workspace", "Email sending", r"_spf\.google\.com"),
    ("spf", "Microsoft 365", "Email sending", r"spf\.protection\.outlook\.com"),
    ("spf", "SendGrid", "Email sending", r"sendgrid\.net"),
    ("spf", "Mailchimp / Mandrill", "Email sending", r"servers\.mcsv\.net|mandrillapp\.com"),
    ("spf", "Amazon SES", "Email sending", r"amazonses\.com"),
    ("spf", "Salesforce", "Email sending", r"_spf\.salesforce\.com|exacttarget\.com"),
    ("spf", "Zendesk", "Email sending", r"mail\.zendesk\.com"),
    ("spf", "HubSpot", "Email sending", r"hubspotemail\.net"),
    ("spf", "Mailgun", "Email sending", r"mailgun\.org"),
    ("spf", "Postmark", "Email sending", r"mtasv\.net"),
    ("spf", "SparkPost", "Email sending", r"sparkpostmail\.com"),
    ("spf", "Zoho", "Email sending", r"zoho\.(com|eu|in)"),
    ("txt", "Google", "SaaS account", r"^google-site-verification="),
    ("txt", "Microsoft 365", "SaaS account", r"^ms=ms\d+"),
    ("txt", "Atlassian", "SaaS account", r"^atlassian-domain-verification="),
    ("txt", "Meta", "SaaS account", r"^facebook-domain-verification="),
    ("txt", "DocuSign", "SaaS account", r"^docusign="),
    ("txt", "Adobe", "SaaS account", r"^adobe-idp-site-verification="),
    ("txt", "Apple", "SaaS account", r"^apple-domain-verification="),
    ("txt", "Zoom", "SaaS account", r"^zoom_verify_"),
    ("txt", "Slack", "SaaS account", r"^slack-domain-verification="),
    ("txt", "Stripe", "SaaS account", r"^stripe-verification="),
    ("txt", "Cisco Webex", "SaaS account", r"^cisco-ci-domain-verification="),
    ("txt", "Dropbox", "SaaS account", r"^dropbox-domain-verification="),
    ("txt", "OpenAI", "SaaS account", r"^openai-domain-verification="),
    ("txt", "HubSpot", "SaaS account", r"^hubspot-developer-verification="),
    ("cname", "Amazon CloudFront", "Hosting / CDN", r"\.cloudfront\.net$"),
    ("cname", "Amazon S3", "Hosting / CDN", r"(^|\.)s3[.-]([a-z0-9-]+\.)?amazonaws\.com$"),
    ("cname", "AWS Elastic Beanstalk", "Hosting / CDN", r"\.elasticbeanstalk\.com$"),
    ("cname", "AWS Elastic Load Balancing", "Hosting / CDN", r"\.elb\.amazonaws\.com$"),
    ("cname", "Azure App Service", "Hosting / CDN", r"\.azurewebsites\.net$"),
    ("cname", "Azure Front Door / CDN", "Hosting / CDN", r"\.(azureedge|azurefd)\.net$"),
    ("cname", "Heroku", "Hosting / CDN", r"\.(herokuapp|herokudns)\.com$"),
    ("cname", "GitHub Pages", "Hosting / CDN", r"\.github\.io$"),
    ("cname", "Shopify", "Commerce", r"\.myshopify\.com$"),
    ("cname", "Fastly", "Hosting / CDN", r"\.fastly(lb)?\.net$"),
    ("cname", "Akamai", "Hosting / CDN", r"\.(akamaiedge|edgekey|edgesuite)\.net$"),
    ("cname", "Cloudflare", "Hosting / CDN", r"\.cdn\.cloudflare\.net$"),
    ("cname", "Netlify", "Hosting / CDN", r"\.netlify\.(app|com)$"),
    ("cname", "Vercel", "Hosting / CDN", r"\.vercel-dns\.com$|\.vercel\.app$"),
    ("cname", "Google Cloud / Firebase", "Hosting / CDN", r"^ghs\.googlehosted\.com$|\.web\.app$|\.firebaseapp\.com$"),
    ("cname", "Zendesk", "Support", r"\.zendesk\.com$"),
    ("cname", "HubSpot", "Marketing", r"\.hubspot\.net$|\.hs-sites\.com$"),
    ("cname", "Wix", "Hosting / CDN", r"\.wixdns\.net$"),
    ("cname", "Squarespace", "Hosting / CDN", r"\.squarespace\.com$"),
    ("cname", "WordPress.com", "Hosting / CDN", r"\.wordpress\.com$"),
    ("cname", "Atlassian Statuspage", "Support", r"\.stspg-customer\.com$"),
)
_PROVIDER_RES = [(s, p, c, re.compile(rx)) for s, p, c, rx in _PROVIDERS]

# Script / stylesheet origins -> (provider, category)
_SCRIPT_HOSTS = (
    ("googletagmanager.com", "Google Tag Manager", "Tag management"),
    ("google-analytics.com", "Google Analytics", "Analytics"),
    ("connect.facebook.net", "Meta Pixel", "Advertising"),
    ("snap.licdn.com", "LinkedIn Insight", "Advertising"),
    ("bat.bing.com", "Microsoft Advertising", "Advertising"),
    ("doubleclick.net", "Google Ads", "Advertising"),
    ("static.hotjar.com", "Hotjar", "Analytics"),
    ("cdn.segment.com", "Segment", "Analytics"),
    ("js.hs-scripts.com", "HubSpot", "Marketing"),
    ("js.hsforms.net", "HubSpot", "Marketing"),
    ("widget.intercom.io", "Intercom", "Support chat"),
    ("js.intercomcdn.com", "Intercom", "Support chat"),
    ("static.zdassets.com", "Zendesk", "Support chat"),
    ("js.driftt.com", "Drift", "Support chat"),
    ("js.stripe.com", "Stripe", "Payments"),
    ("www.paypal.com", "PayPal", "Payments"),
    ("cdn.cookielaw.org", "OneTrust", "Consent"),
    ("consent.cookiebot.com", "Cookiebot", "Consent"),
    ("www.google.com", "Google (reCAPTCHA / Maps)", "Security"),
    ("www.gstatic.com", "Google", "CDN"),
    ("www.recaptcha.net", "Google reCAPTCHA", "Security"),
    ("challenges.cloudflare.com", "Cloudflare Turnstile", "Security"),
    ("maps.googleapis.com", "Google Maps", "Maps"),
    ("fonts.googleapis.com", "Google Fonts", "Fonts"),
    ("use.typekit.net", "Adobe Fonts", "Fonts"),
    ("kit.fontawesome.com", "Font Awesome", "Fonts"),
    ("assets.adobedtm.com", "Adobe Experience Platform", "Tag management"),
    ("cdn.optimizely.com", "Optimizely", "Analytics"),
    ("browser.sentry-cdn.com", "Sentry", "Monitoring"),
    ("js-agent.newrelic.com", "New Relic", "Monitoring"),
    ("cdn.shopify.com", "Shopify", "Commerce"),
    ("player.vimeo.com", "Vimeo", "Video"),
    ("www.youtube.com", "YouTube", "Video"),
)


def script_provider(host):
    """(provider, category) for a script/stylesheet origin, or None."""
    host = str(host or "").lower()
    for domain, provider, category in _SCRIPT_HOSTS:
        if _host_matches(host, domain):
            return provider, category
    if host in PUBLIC_CDNS:
        return PUBLIC_CDNS[host], "CDN"
    return None


def _spf_includes(txt_values):
    out = []
    for value in txt_values or ():
        v = str(value).strip().strip('"').lower()
        if v.startswith("v=spf1"):
            out.extend(t.split(":", 1)[1] for t in v.split() if t.startswith("include:"))
            out.extend(t.split("=", 1)[1] for t in v.split() if t.startswith("redirect="))
    return out


def providers_from_records(domain, records):
    """Service providers implied by one domain's DNS records.

    `records` is {mx, ns, txt, cname_targets: [{host, cname}]}; any key may be
    missing (lookup failed or older scan). Returns [{provider, category,
    source, domain, evidence}] with one row per (provider, source).
    """
    records = records or {}
    values = {
        "mx": [str(v).split()[-1] for v in records.get("mx") or () if str(v).split()],
        "ns": list(records.get("ns") or ()),
        "spf": _spf_includes(records.get("txt")),
        "txt": [str(v).strip().strip('"') for v in records.get("txt") or ()],
        "cname": [str(c.get("cname") or "") for c in records.get("cname_targets") or ()
                  if isinstance(c, dict)],
    }
    out, seen = [], set()
    for source, provider, category, rx in _PROVIDER_RES:
        for value in values.get(source) or ():
            v = value.strip().lower().rstrip(".")
            if v and rx.search(v) and (provider, source) not in seen:
                seen.add((provider, source))
                evidence = v if source != "txt" else v.split("=", 1)[0] + "=…"
                out.append({"provider": provider, "category": category,
                            "source": source, "domain": domain,
                            "evidence": evidence[:120]})
                break
    return out
