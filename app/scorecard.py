"""scorecard.py — per-domain external posture rating over the asset inventories.

Seven risk factors are each scored 0-100 on their own and combined by weight
into one rating per domain — the shape commercial security-rating platforms
use, built only from passive evidence the scan already captures:

  vulnerability   CVE-bearing software and packages found on the domain's hosts
  exposed         high-risk services reachable from the internet
  certificates    expired / expiring / mismatched / untrusted TLS certs
  email_dns       SPF, DMARC, DKIM, DNSSEC, CAA, MTA-STS posture
  application     HTTPS, HSTS, browser security headers, cookie flags
  dependencies    third-party scripts: compromised CDNs, end-of-life
                  libraries, mixed content, unpinned or unverified CDN assets
  disclosure      software versions advertised in headers and markup

Design rules, following risk.py and dns_posture.py:

  - DETERMINISTIC. Score is a pure function of the scan snapshot. Nothing is
    persisted here and no stored severity is mutated; the score is a separate,
    fully itemized field so an analyst or auditor can see exactly why one
    domain outranks another.

  - ITEMIZED. Every deduction is recorded as {code, type, label, points,
    detail}. `points` are factor points (0-100 scale); `type` keys the issue
    catalog (ISSUE_TYPES) that explains the risk and the fix. A score without
    its arithmetic is an opinion; this is arithmetic.

  - EXACT PROJECTIONS. `gain` — the rating change from fixing an item — is
    computed by re-running this model with the item excluded, so budgets and
    caps are honoured rather than approximated: fixing one of two critical
    CVEs gains nothing while the other still holds the cap.

  - UNKNOWN IS NOT GOOD. A factor with no data for a domain (never scanned, no
    certs captured, resolver outage) is EXCLUDED from both numerator and
    denominator. A domain whose certificates were never inspected must not
    score as though it had clean certificates. When every factor is unknown
    the grade is '?' and the score is 0 with `unknown: true`.

  - NOT DOUBLE-COUNTED. The exposed-services factor looks only at reachable
    service ports; CVEs are scored once, in the vulnerability factor — that
    includes CVEs in front-end packages, so the dependencies factor scores
    only how packages are sourced and maintained. Advertising a version
    (disclosure) is a separate issue from the flaw that version may carry.

  - CAPPED. A domain cannot buy back its grade with good hygiene elsewhere:
    confirmed critical exposure (a critical CVE match, a compromised CDN, a
    subdomain open to takeover) caps the total at 60.
"""
import ipaddress
import re
from collections import defaultdict

import dependencies as deps
import dns_posture

# Factor weights (sum to 100). Vulnerable software and reachable high-risk
# services dominate because they are what attackers actually exploit; header
# and banner hygiene matters, but never outweighs an exposed database.
WEIGHTS = {
    "vulnerability": 25,
    "exposed": 20,
    "certificates": 15,
    "email_dns": 15,
    "application": 10,
    "dependencies": 10,
    "disclosure": 5,
}

PILLAR_LABELS = {
    "vulnerability": "Vulnerability exposure",
    "exposed": "Exposed services",
    "certificates": "Certificate hygiene",
    "email_dns": "Email & DNS posture",
    "application": "Application security",
    "dependencies": "Web dependencies",
    "disclosure": "Information disclosure",
}

_GRADE_BANDS = (("A", 90), ("B", 80), ("C", 70), ("D", 55), ("F", 0))

# Ports that should essentially never be reachable from the public internet.
# (port, factor points, label)
HIGH_RISK_PORTS = (
    (23, 40, "Telnet"),
    (445, 40, "SMB"),
    (3389, 40, "RDP"),
    (5900, 30, "VNC"),
    (2375, 40, "Docker API"),
    (2376, 40, "Docker API (TLS)"),
    (3306, 30, "MySQL"),
    (5432, 30, "PostgreSQL"),
    (1433, 30, "MSSQL"),
    (27017, 40, "MongoDB"),
    (6379, 40, "Redis"),
    (9200, 30, "Elasticsearch"),
    (11211, 30, "memcached"),
    (5984, 30, "CouchDB"),
)

# Vulnerability deductions by worst matched CVE severity. A vulnerable package
# is evidence, not proof of exploitability, so each is a bounded deduction
# rather than a zeroing.
_CVE_POINTS = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 4}
# A CVE that CISA lists as exploited in the wild weighs at least this much,
# whatever its CVSS: attackers already have a working technique.
_KEV_POINTS = 24
_CVE_POINTS_MAX = 85          # one host cannot consume the whole factor

# Certificate deductions by issue type.
_CERT_POINTS = {
    "expired": 32,
    "hostname mismatch": 24,
    "untrusted chain": 20,
    "self-signed": 12,
    "expiring soon": 8,
}
_CERT_POINTS_MAX = 88
_CERT_TYPES = {
    "expired": "cert-expired",
    "hostname mismatch": "cert-mismatch",
    "untrusted chain": "cert-untrusted",
    "self-signed": "cert-self-signed",
    "expiring soon": "cert-expiring",
}

# Web checks are aggregated per domain: (points per affected host, cap), so a
# large estate with one systemic gap is not zeroed by host count alone.
_WEB_POINTS = {
    "no-https": (20, 60),
    "no-hsts": (8, 24),
    "no-csp": (4, 12),
    "no-frame-protection": (4, 12),
    "no-nosniff": (3, 9),
    "insecure-cookie": (6, 18),
    "server-version": (10, 30),
    "powered-by": (6, 18),
    "aspnet-version": (8, 24),
    "generator-version": (6, 18),
    "dep-compromised": (60, 100),
    "dep-eol": (12, 36),
    "dep-mixed-content": (10, 30),
    "dep-no-sri": (5, 20),
    "dep-unpinned": (4, 16),
}
_APP_TYPES = ("no-https", "no-hsts", "no-csp", "no-frame-protection",
              "no-nosniff", "insecure-cookie")
_DISCLOSURE_TYPES = ("server-version", "powered-by", "aspnet-version",
                     "generator-version")
_DEPENDENCY_TYPES = ("dep-compromised", "dep-eol", "dep-mixed-content",
                     "dep-no-sri", "dep-unpinned")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Issue types that cap the domain rating like a critical CVE does: each
# means someone else can run code or serve content under the domain.
_CRITICAL_TYPES = ("dep-compromised", "dns-takeover")


def _issue(factor, severity, title, why, fix):
    return {"factor": factor, "severity": severity, "title": title,
            "why": why, "fix": fix}


# The issue catalog: what each deduction type means and how to fix it. Every
# deduction's `type` is a key here, so the dashboard, the planner and the
# report explain an issue in one consistent voice.
ISSUE_TYPES = {
    "vuln-critical": _issue(
        "vulnerability", "critical", "Software with a critical CVE match",
        "A disclosed version matches a CVE rated critical — the class of flaw "
        "most often exploited at scale.",
        "Confirm the installed version and that the CVE applies, upgrade to a "
        "fixed release, then rescan."),
    "vuln-kev": _issue(
        "vulnerability", "critical", "Software with a known-exploited CVE",
        "CISA lists a matched CVE as exploited in the wild (KEV catalog), so "
        "working attack techniques already exist.",
        "Treat as urgent: upgrade to a fixed release before the KEV due date, "
        "then rescan."),
    "vuln-high": _issue(
        "vulnerability", "high", "Software with a high-severity CVE match",
        "A disclosed version matches a high-severity CVE.",
        "Confirm applicability, upgrade to a fixed release, then rescan."),
    "vuln-medium": _issue(
        "vulnerability", "medium", "Software with other CVE matches",
        "A disclosed version matches CVEs of lower or unrated severity.",
        "Confirm applicability and schedule the upgrade with routine patching."),
    "cert-expired": _issue(
        "certificates", "high", "Expired TLS certificate",
        "Clients reject the connection, or users learn to click through "
        "certificate warnings.",
        "Renew the certificate and automate renewal (for example ACME), then "
        "rescan."),
    "cert-mismatch": _issue(
        "certificates", "high", "Certificate does not cover the hostname",
        "Clients cannot verify they reached the intended server.",
        "Issue a certificate whose SANs include this hostname, or stop "
        "serving TLS on it."),
    "cert-untrusted": _issue(
        "certificates", "medium", "Untrusted certificate chain",
        "Missing intermediates or a private CA make clients fail validation.",
        "Serve the full chain from a publicly trusted CA."),
    "cert-self-signed": _issue(
        "certificates", "medium", "Self-signed certificate",
        "No third party vouches for the server's identity.",
        "Replace it with a certificate from a publicly trusted CA."),
    "cert-expiring": _issue(
        "certificates", "low", "Certificate expiring soon",
        "An expiry inside the warning window becomes an outage if renewal "
        "fails.",
        "Renew now and confirm automated renewal works."),
    "dns-spf": _issue(
        "email_dns", "medium", "SPF missing or weak",
        "Without a strict SPF policy, anyone can send mail that claims to "
        "come from the domain.",
        "Publish one v=spf1 record listing your senders and ending in -all "
        "or ~all."),
    "dns-dmarc": _issue(
        "email_dns", "medium", "DMARC missing or not enforcing",
        "DMARC is what tells receivers to reject spoofed mail; p=none only "
        "monitors.",
        "Publish DMARC with a reporting address, then move to p=quarantine "
        "or p=reject."),
    "dns-dkim": _issue(
        "email_dns", "low", "No DKIM key found",
        "Receivers cannot verify outgoing mail was signed by the domain.",
        "Enable DKIM signing at your mail provider and publish the selector."),
    "dns-dnssec": _issue(
        "email_dns", "low", "DNSSEC not enabled",
        "Resolvers cannot detect forged DNS answers for the zone.",
        "Sign the zone and publish the DS record at the registrar."),
    "dns-caa": _issue(
        "email_dns", "low", "No CAA record",
        "Any certificate authority may issue certificates for the domain.",
        "Publish CAA records naming the CAs you actually use."),
    "dns-mta_sts": _issue(
        "email_dns", "low", "No MTA-STS policy",
        "Inbound mail transport can be downgraded to plaintext.",
        "Publish an MTA-STS policy and its _mta-sts TXT record."),
    "dns-takeover": _issue(
        "email_dns", "critical", "Dangling CNAME (subdomain takeover risk)",
        "A subdomain points at a third-party service that no longer exists; "
        "whoever claims it controls content on your domain.",
        "Remove the stale DNS record or restore the intended service, then "
        "rescan."),
    "dns-other": _issue(
        "email_dns", "low", "Other DNS posture gaps",
        "Posture checks lost points that are not attributed to one record.",
        "Review the Email & DNS posture panel for this domain."),
    "no-https": _issue(
        "application", "high", "Website served without HTTPS",
        "Traffic can be read and modified in transit, including credentials.",
        "Serve the site over HTTPS with a trusted certificate and redirect "
        "HTTP to it."),
    "no-hsts": _issue(
        "application", "medium", "HTTPS without HSTS",
        "Browsers may still make a first plaintext request that can be "
        "intercepted and downgraded.",
        "Send Strict-Transport-Security with a max-age of at least six "
        "months on every HTTPS response."),
    "no-csp": _issue(
        "application", "low", "No Content-Security-Policy",
        "Nothing limits which scripts the page may load, so an injection "
        "bug becomes script execution.",
        "Add a Content-Security-Policy, starting in report-only mode if "
        "needed."),
    "no-frame-protection": _issue(
        "application", "low", "No clickjacking protection",
        "Other sites can frame the page and trick users into clicking it.",
        "Send X-Frame-Options: DENY or a CSP frame-ancestors directive."),
    "no-nosniff": _issue(
        "application", "low", "Missing X-Content-Type-Options",
        "Browsers may guess content types and execute uploaded files as "
        "script.",
        "Send X-Content-Type-Options: nosniff."),
    "insecure-cookie": _issue(
        "application", "medium", "Cookie set without the Secure flag",
        "The cookie can leak over any plaintext request to the host.",
        "Set the Secure flag (and HttpOnly for session cookies)."),
    "server-version": _issue(
        "disclosure", "low", "Server header reveals the software version",
        "A precise version lets attackers match known CVEs without probing.",
        "Configure the server or proxy to omit version details (for example "
        "server_tokens off or ServerTokens Prod)."),
    "powered-by": _issue(
        "disclosure", "low", "X-Powered-By reveals the application stack",
        "It advertises the framework and often its version to every client.",
        "Remove the X-Powered-By header at the application or proxy."),
    "aspnet-version": _issue(
        "disclosure", "low", "X-AspNet-Version reveals the framework version",
        "It advertises the exact .NET version to every client.",
        "Disable it with enableVersionHeader=false in web.config."),
    "generator-version": _issue(
        "disclosure", "low", "Generator tag reveals the CMS version",
        "A versioned generator tag lets attackers match CMS CVEs directly.",
        "Remove the generator meta tag or its version, and keep the CMS "
        "patched."),
    "dep-compromised": _issue(
        "dependencies", "critical", "Script loaded from a compromised CDN",
        "The page executes code from a domain known to have served malware; "
        "whoever controls it can read and alter everything on the page.",
        "Remove the reference now, self-host a vetted copy or use a trusted "
        "mirror, and review the site for injected content."),
    "dep-eol": _issue(
        "dependencies", "medium", "End-of-life front-end library",
        "The library line no longer receives security fixes, so newly found "
        "flaws stay open.",
        "Migrate to a supported major version of the library."),
    "dep-mixed-content": _issue(
        "dependencies", "medium", "Script or stylesheet loaded over HTTP",
        "An HTTPS page pulling assets over plaintext lets a network attacker "
        "swap them; browsers block or warn on it.",
        "Load every asset over HTTPS."),
    "dep-no-sri": _issue(
        "dependencies", "low", "CDN script without Subresource Integrity",
        "If the CDN or the file is tampered with, the browser runs the "
        "modified script without noticing.",
        "Add integrity=\"sha384-…\" and crossorigin=\"anonymous\" to "
        "versioned CDN script tags."),
    "dep-unpinned": _issue(
        "dependencies", "low", "CDN package without a pinned version",
        "A floating tag (@latest or a major-only range) silently changes the "
        "code your page runs when the package is republished.",
        "Reference an exact version (name@1.2.3) and add an integrity hash."),
}
for _port, _pts, _label in HIGH_RISK_PORTS:
    ISSUE_TYPES["port-%d" % _port] = _issue(
        "exposed", "high" if _pts >= 40 else "medium",
        "%s reachable from the internet" % _label,
        "Remote-access, database and cache services are routinely "
        "brute-forced or exploited when exposed, and many ship without "
        "authentication.",
        "Close the port at the firewall or restrict it to known networks or "
        "a VPN, then rescan.")


def grade_for(score):
    """Letter grade for a 0-100 score."""
    for grade, floor in _GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


def _deduction(code, type_, label, points, detail=""):
    return {"code": code, "type": type_, "label": label,
            "points": int(points), "detail": str(detail)[:200]}


def _excluded(item, exclude):
    return item["code"] in exclude or item["type"] in exclude


def _apply_budget(candidates, budget, exclude=()):
    """Drop excluded candidates, then spend `budget` factor points in order.

    Candidates arrive worst-first, so the most serious items are always
    scored and lower-priority ones are dropped once the budget is spent.
    """
    out, total = [], 0
    for c in candidates:
        if _excluded(c, exclude):
            continue
        pts = min(c["points"], budget - total)
        if pts <= 0:
            break
        total += pts
        out.append(dict(c, points=pts))
    return out


def _verdict(pillar, items, available=True, note="", score=None):
    """Turn a factor's deductions into a scored verdict.

    `score` is 0-100 for the factor; `earned`/`max` express the same thing in
    weighted rating points.
    """
    weight = WEIGHTS[pillar]
    if not available:
        return {
            "pillar": pillar, "label": PILLAR_LABELS[pillar],
            "max": weight, "earned": None, "score": None, "grade": "?",
            "deductions": [], "unknown": True, "note": note or "no data",
        }
    if score is None:
        score = max(0, 100 - sum(i["points"] for i in items))
    return {
        "pillar": pillar, "label": PILLAR_LABELS[pillar],
        "max": weight, "earned": round(weight * score / 100.0, 1),
        "score": score, "grade": grade_for(score),
        "deductions": items, "unknown": False, "note": note,
    }


# --------------------------------------------------------------------------
# factor builders — each takes only pre-gathered rows
# --------------------------------------------------------------------------
def _worst_severity(cves, severity_map):
    """Highest severity among `cves` given {cve: 'CRITICAL'|'HIGH'|...}."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    best = None
    for c in cves or ():
        sev = severity_map.get(str(c).upper())
        if sev and (best is None or order.get(sev, 9) < order.get(best, 9)):
            best = sev
    return best


def _vuln_code(row):
    return "vuln:%s:%s" % (row.get("host"), row.get("product"))


def _vuln_type(sev, exploited=False):
    if sev == "CRITICAL":
        return "vuln-critical"      # caps the rating; KEV is noted in the detail
    if exploited:
        return "vuln-kev"
    return {"HIGH": "vuln-high"}.get(sev, "vuln-medium")


def vulnerability_pillar(software_rows, severity_map=None, assessed=True, exclude=(),
                         exploited=()):
    """Deductions for CVE-bearing software on a domain's hosts.

    `software_rows` are inventory rows already filtered to this domain.
    `severity_map` maps CVE id -> severity; when a CVE is absent the row's
    worst severity is unknown and is treated as MEDIUM (the map only carries
    CRITICAL/HIGH entries, so an unknown id should not be scored as critical).

    `assessed` distinguishes the two cases that look identical from an empty
    row list: hosts were fingerprinted and simply disclosed no versioned
    software (we looked — clean), versus no host was fingerprinted at all (we
    did not look — unknown, which must not read as clean).

    `exploited` is the set of CVE ids listed in CISA KEV (from live intel);
    such a row ranks right after critical ones and weighs at least
    _KEV_POINTS.
    """
    severity_map = severity_map or {}
    exploited = set(exploited or ())
    if not software_rows:
        if not assessed:
            return _verdict("vulnerability", [], available=False,
                            note="no hosts fingerprinted")
        return _verdict("vulnerability", [], available=True,
                        note="no versioned software disclosed")
    def rank(r):
        sev = _worst_severity(r.get("related_cves"), severity_map) or "MEDIUM"
        kev = bool(exploited.intersection(r.get("related_cves") or ()))
        return ({"CRITICAL": 0}.get(sev, 1 if kev else 2 + {"HIGH": 0, "MEDIUM": 1}.get(sev, 2)),
                -r.get("cve_count", 0), str(r.get("host")), str(r.get("product")))

    candidates = []
    # one deduction per vulnerable product row, worst first, bounded in aggregate
    for row in sorted(software_rows, key=rank):
        if not row.get("cve_count"):
            continue
        sev = _worst_severity(row.get("related_cves") or [], severity_map) or "MEDIUM"
        kev = sorted(exploited.intersection(row.get("related_cves") or ()))
        points = _CVE_POINTS.get(sev, _CVE_POINTS["MEDIUM"])
        candidates.append(_deduction(
            _vuln_code(row), _vuln_type(sev, bool(kev)),
            "%s %s on %s" % (row.get("product"), row.get("version") or "(no version)",
                             row.get("host")),
            max(points, _KEV_POINTS) if kev else points,
            "%d CVE(s), worst %s%s" % (row.get("cve_count", 0), sev,
                                       "; known exploited: " + ", ".join(kev[:3]) if kev else "")))
    return _verdict("vulnerability", _apply_budget(candidates, _CVE_POINTS_MAX, exclude),
                    note="%d of %d components carry CVEs"
                         % (sum(1 for r in software_rows if r.get("cve_count")),
                            len(software_rows)))


def certificate_pillar(cert_rows, exclude=()):
    """Deductions for certificate hygiene on a domain's hosts."""
    if not cert_rows:
        return _verdict("certificates", [], available=False,
                        note="no certificates captured")
    candidates = []
    for row in cert_rows:
        for issue in (row.get("issues") or []):
            pts = _CERT_POINTS.get(issue)
            if not pts:
                continue
            candidates.append(_deduction(
                "cert:%s:%s" % (row.get("host"), issue), _CERT_TYPES[issue],
                "%s on %s" % (issue, row.get("host")), pts,
                row.get("not_after") or ""))
    candidates.sort(key=lambda d: -d["points"])
    ok = sum(1 for r in cert_rows if not r.get("issues"))
    return _verdict("certificates", _apply_budget(candidates, _CERT_POINTS_MAX, exclude),
                    note="%d of %d certificates clean" % (ok, len(cert_rows)))


def _apportion(total, shares):
    """Split integer `total` across {key: float share} by largest remainder,
    so the attributed deductions sum exactly to the points actually lost."""
    raw = {k: v for k, v in shares.items() if v > 0}
    weight = sum(raw.values())
    if total <= 0 or weight <= 0:
        return {}
    scaled = {k: total * v / weight for k, v in raw.items()}
    out = {k: int(v) for k, v in scaled.items()}
    for k in sorted(scaled, key=lambda k: (out[k] - scaled[k], k))[:total - sum(out.values())]:
        out[k] += 1
    return {k: v for k, v in out.items() if v > 0}


def _fixed_checks(checks, exclude):
    """`checks` with every excluded (and observed) check treated as passing."""
    out = dict(checks)
    for name in list(dns_posture.CHECK_WEIGHTS) + ["takeover"]:
        if "dns-" + name not in exclude and "dns:" + name not in exclude:
            continue
        if name == "takeover":
            out[name] = []
        elif not (out.get(name) or {}).get("unknown"):
            out[name] = {"present": True, "severity": None, "issues": []}
    return out


def _dns_from_checks(dns_result, checks, exclude):
    """Attribute the posture score's loss to the individual checks exactly.

    The factor score is dns_posture's own score (recomputed by dns_posture
    with excluded checks passing, for projections), and each check's share
    follows the same weights and partial credit that produced it.
    """
    if any(str(e).startswith(("dns-", "dns:")) for e in exclude):
        checks = _fixed_checks(checks, exclude)
        score, _ = dns_posture._grade(checks, [])
    else:
        score = int(float(dns_result.get("score") or 0))
    possible = 0
    shares = {}
    for name, weight in dns_posture.CHECK_WEIGHTS.items():
        credit = dns_posture.check_credit(checks.get(name) or {})
        if credit is None:
            continue
        possible += weight
        shares[name] = weight * (1.0 - credit)
    shares = {k: 100.0 * v / possible for k, v in shares.items()} if possible else {}
    takeover = checks.get("takeover") or []
    if takeover:
        shares["takeover"] = max(0.0, 100.0 - sum(shares.values()) - score)
    points = _apportion(100 - score, shares)
    if takeover:
        # A dangling CNAME stays listed even when the score was already below
        # the takeover cap and it costs no further DNS points: it is critical
        # exposure in its own right and caps the domain rating.
        points.setdefault("takeover", 0)
    items = []
    for name, pts in sorted(points.items(), key=lambda kv: (-kv[1], kv[0])):
        if name == "takeover":
            messages = ["%s: %s" % (t.get("host"), m)
                        for t in takeover for m in (t.get("issues") or [])]
        else:
            messages = list((checks.get(name) or {}).get("issues") or [])
        label = (messages[0] if messages else "%s check incomplete" % name)[:120]
        items.append(_deduction("dns:%s" % name, "dns-%s" % name, label, pts,
                                "; ".join(messages[1:]) or name))
    return _verdict("email_dns", items, score=score,
                    note="posture score %d/100" % score)


def email_dns_pillar(dns_result, exclude=()):
    """Deductions from the DNS posture verdict for the domain itself.

    Reuses dns_posture's 0-100 score rather than re-deriving it, so the
    scorecard and the posture panel can never disagree. With the per-check
    detail present the loss is attributed exactly; older verdicts without it
    fall back to a severity-weighted split of the same loss.
    """
    if not dns_result or dns_result.get("grade") in (None, "?"):
        return _verdict("email_dns", [], available=False,
                        note="DNS posture not assessed")
    checks = dns_result.get("checks")
    if isinstance(checks, dict) and checks:
        return _dns_from_checks(dns_result, checks, exclude)
    base = int(float(dns_result.get("score") or 0))
    items = []
    remaining = 100 - base
    for issue in (dns_result.get("issues") or []):
        if remaining <= 0:
            break
        share = min({"HIGH": 32, "MEDIUM": 20, "LOW": 8}.get(issue.get("severity"), 4),
                    remaining)
        remaining -= share
        items.append(_deduction(
            "dns:%s" % issue.get("check"), "dns-%s" % issue.get("check"),
            issue.get("message", "")[:120], share, issue.get("check", "")))
    if remaining > 0:
        items.append(_deduction("dns:other", "dns-other", "other posture gaps",
                                remaining, ""))
    kept = [i for i in items if not _excluded(i, exclude)]
    score = min(100, base + sum(i["points"] for i in items if _excluded(i, exclude)))
    return _verdict("email_dns", kept, score=score,
                    note="posture score %d/100" % base)


def exposed_pillar(service_rows, exclude=()):
    """Deductions for high-risk services reachable on a domain's hosts.

    `service_rows` is [{host, open: {port: name}}] for this domain's hosts.
    """
    if service_rows is None:
        return _verdict("exposed", [], available=False, note="no service scan")
    candidates = []
    for row in service_rows:
        open_ports = {str(p) for p in (row.get("open") or {})}
        for port, pts, label in HIGH_RISK_PORTS:
            if str(port) in open_ports:
                candidates.append(_deduction(
                    "exposed:%s:%s" % (row.get("host"), port), "port-%d" % port,
                    "%s (%s) reachable on %s" % (label, port, row.get("host")),
                    pts, ""))
    candidates.sort(key=lambda d: -d["points"])
    return _verdict("exposed", _apply_budget(candidates, 100, exclude),
                    note="%d host(s) probed" % len(service_rows))


_VERSION_RE = re.compile(r"\d+\.\d+")
_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.I)
_CONTENT_CODE_RE = re.compile(r"^(2\d\d|401|403)$")
_COOKIE_FLAGS_RE = re.compile(r"\(([^)]*)\)\s*$")


def _web_responses(web_rows):
    """Fingerprints that carry a usable HTTP response (scheme known, < 500).

    Error pages carry unreliable header sets, matching the scanner's own
    security-header findings.
    """
    out = []
    for r in web_rows or ():
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or "")
        code = str(r.get("code") or "")
        if url.startswith(("http://", "https://")) and code.isdigit() \
                and not code.startswith("5"):
            out.append(r)
    return out


def _cookie_secure(entry):
    """The scanner records cookies as 'name (HttpOnly,Secure,...)' or 'name'."""
    m = _COOKIE_FLAGS_RE.search(str(entry))
    return bool(m) and "secure" in [f.strip().lower() for f in m.group(1).split(",")]


def _web_findings(responses):
    """{issue type: [hosts]} for the application-security and disclosure checks."""
    found = defaultdict(set)
    for r in responses:
        host = str(r.get("host") or "")
        https = str(r["url"]).startswith("https://")
        if not https:
            # An http:// fingerprint only says the HTTPS fetch failed. With a
            # certificate captured for the host, TLS IS served, typically with
            # a certificate the fetch refused (expired, mismatched,
            # self-signed), which the certificate factor already scores.
            if not r.get("tls_seen"):
                found["no-https"].add(host)
        else:
            m = _HSTS_MAX_AGE_RE.search(str(r.get("strict-transport-security") or ""))
            if not m or int(m.group(1)) <= 0:
                found["no-hsts"].add(host)
        # page-level headers only matter where a document was served
        if _CONTENT_CODE_RE.match(str(r["code"])):
            csp = r.get("content-security-policy")
            if https and not csp:
                found["no-csp"].add(host)
            # The scanner keeps only the first 120 characters of a header, so
            # a CSP frame-ancestors directive may be cut off: any CSP counts.
            if not r.get("x-frame-options") and not csp:
                found["no-frame-protection"].add(host)
            if str(r.get("x-content-type-options") or "").strip().lower() != "nosniff":
                found["no-nosniff"].add(host)
        if https and any(not _cookie_secure(c) for c in (r.get("cookies") or [])):
            found["insecure-cookie"].add(host)
        if _VERSION_RE.search(str(r.get("server") or "")):
            found["server-version"].add(host)
        if str(r.get("x-powered-by") or "").strip():
            found["powered-by"].add(host)
        if str(r.get("x-aspnet-version") or "").strip():
            found["aspnet-version"].add(host)
        if _VERSION_RE.search("%s %s" % (r.get("generator") or "", r.get("x-generator") or "")):
            found["generator-version"].add(host)
    return found


def _web_pillar(pillar, types, web_rows, exclude=()):
    responses = _web_responses(web_rows)
    if not responses:
        return _verdict(pillar, [], available=False, note="no web responses captured")
    return _aggregate(pillar, types, _web_findings(responses), {}, exclude,
                      note="%d web response%s examined"
                           % (len(responses), "" if len(responses) == 1 else "s"))


def _aggregate(pillar, types, found, examples, exclude, note):
    """One deduction per issue type, scaled by affected hosts up to its cap.

    `examples` optionally maps type -> descriptors (e.g. 'angularjs 1.7.9')
    shown ahead of the host list.
    """
    items = []
    for t in types:
        hosts = sorted(found.get(t) or ())
        item = _deduction("%s:%s" % (pillar, t), t, "", 0)
        if not hosts or _excluded(item, exclude):
            continue
        per_host, cap = _WEB_POINTS[t]
        item.update(
            label="%s (%d host%s)" % (ISSUE_TYPES[t]["title"], len(hosts),
                                      "" if len(hosts) == 1 else "s"),
            points=min(cap, per_host * len(hosts)),
            detail=", ".join(hosts[:3]) + (" +%d more" % (len(hosts) - 3)
                                           if len(hosts) > 3 else ""),
            hosts=hosts[:25], count=len(hosts))
        shown = sorted(examples.get(t) or ())
        if shown:
            item["detail"] = ("%s · %s" % (", ".join(shown[:3]), item["detail"]))[:200]
        items.append(item)
    items.sort(key=lambda d: -d["points"])
    return _verdict(pillar, items, note=note)


def application_pillar(web_rows, exclude=()):
    """HTTPS, HSTS, browser security headers and cookie flags."""
    return _web_pillar("application", _APP_TYPES, web_rows, exclude)


def disclosure_pillar(web_rows, exclude=()):
    """Software versions advertised in response headers and markup."""
    return _web_pillar("disclosure", _DISCLOSURE_TYPES, web_rows, exclude)


def dependencies_pillar(web_rows, exclude=()):
    """How third-party scripts and stylesheets are sourced and maintained.

    Assessed only where the scanner examined page markup (`assets` present;
    an empty list means it looked and found none). Scans from before asset
    capture leave this factor unknown rather than clean.
    """
    pages = [r for r in _web_responses(web_rows) if isinstance(r.get("assets"), list)]
    if not pages:
        return _verdict("dependencies", [], available=False,
                        note="no page markup examined")
    found, examples = defaultdict(set), defaultdict(set)
    total = 0
    for r in pages:
        for asset in r["assets"]:
            if not isinstance(asset, dict):
                continue
            total += 1
            for t, label in deps.asset_issues(asset).items():
                found[t].add(str(r.get("host") or ""))
                examples[t].add(str(label))
    return _aggregate("dependencies", _DEPENDENCY_TYPES, found, examples, exclude,
                      note="%d asset%s on %d page%s" % (
                          total, "" if total == 1 else "s",
                          len(pages), "" if len(pages) == 1 else "s"))


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------
def scorecard_for_domain(domain, software_rows=None, cert_rows=None,
                         dns_result=None, service_rows=None,
                         severity_map=None, software_assessed=None,
                         web_rows=None, exclude=(), explain=True, exploited=()):
    """Build one domain's scorecard from already-filtered rows.

    Returns {domain, score, grade, coverage, confidence, pillars[], issues[],
    issue_types[], unknown, critical_cap, coverage_cap}.

    `software_assessed` defaults to None meaning "infer": assessed when any
    fingerprint rows exist. It must be passed explicitly only when the caller
    knows the scan looked at hosts and found no versioned software — the
    default must never claim a domain was examined when nothing was supplied.

    `web_rows` are this domain's fingerprint snippets, each with its `host`;
    without a usable HTTP response both web factors are unknown.

    `exploited` is the set of CVE ids known to be exploited (CISA KEV).

    `exclude` holds deduction codes or issue types to treat as fixed — the
    score planner's what-if input. With `explain`, every deduction and issue
    type carries `gain`: the exact score change from fixing it.

    `coverage` is the share of the total weight that could actually be
    assessed. It exists because excluding unknown factors from the average —
    the right call, since an outage must not read as a finding — means a
    barely-examined domain could otherwise score 100. A grade is never issued
    above C when any factor is missing.
    """
    if software_assessed is None:
        software_assessed = bool(software_rows)
    exclude = frozenset(exclude or ())
    pillars = [
        vulnerability_pillar(software_rows or [], severity_map,
                             assessed=software_assessed, exclude=exclude,
                             exploited=exploited),
        certificate_pillar(cert_rows or [], exclude),
        email_dns_pillar(dns_result, exclude),
        exposed_pillar(service_rows, exclude),
        application_pillar(web_rows, exclude),
        dependencies_pillar(web_rows, exclude),
        disclosure_pillar(web_rows, exclude),
    ]
    known = [p for p in pillars if not p.get("unknown")]
    coverage = int(round(100.0 * sum(p["max"] for p in known) / sum(WEIGHTS.values())))
    # A card is "unknown" when essentially nothing was examined. The software
    # factor can be marked assessed on empty input (we looked, nothing
    # disclosed), which alone would otherwise produce a confident 100 — so
    # require real coverage before calling a card assessed.
    if not known or coverage < 30:
        return {
            "domain": domain, "score": 0, "grade": "?",
            "coverage": coverage, "confidence": "none",
            "pillars": pillars, "issues": [], "issue_types": [], "unknown": True,
            "critical_cap": False, "coverage_cap": False,
        }
    possible = sum(p["max"] for p in known)
    score = int(round(sum(p["max"] * p["score"] for p in known) / float(possible)))

    # A confirmed critical CVE on a reachable host, a page executing code from
    # a compromised CDN, or a subdomain open to takeover is a hard cap: clean
    # hygiene elsewhere must not launder it into a B. Every software row is
    # checked, not only those that fit the deduction budget.
    critical = any(
        r.get("cve_count")
        and _worst_severity(r.get("related_cves"), severity_map or {}) == "CRITICAL"
        and _vuln_code(r) not in exclude and "vuln-critical" not in exclude
        for r in (software_rows or [])) or any(
        d["type"] in _CRITICAL_TYPES for p in pillars for d in p["deductions"])
    capped = False
    if critical and score > 60:
        score = 60
        capped = True

    grade = grade_for(score)
    coverage_cap = False
    # A grade is a claim about the whole picture, so it cannot exceed what was
    # actually examined: with a major factor missing (e.g. no software was
    # ever fingerprinted) the arithmetic may read 100 but the evidence does
    # not support an A. Tiers are deliberately blunt — this is a confidence
    # downgrade, not another score.
    if coverage < 60:
        if grade in ("A", "B", "C"):
            grade = "D"
            coverage_cap = True
    elif coverage < 100:
        if grade in ("A", "B"):
            grade = "C"
            coverage_cap = True

    if coverage >= 85:
        confidence = "high"
    elif coverage >= 60:
        confidence = "partial"
    else:
        confidence = "low"

    card = {
        "domain": domain, "score": score, "grade": grade,
        "coverage": coverage, "confidence": confidence,
        "pillars": pillars, "unknown": False,
        "critical_cap": capped, "coverage_cap": coverage_cap,
        "critical_exposure": critical,
    }
    if explain:
        def rerun(more):
            return scorecard_for_domain(
                domain, software_rows, cert_rows, dns_result, service_rows,
                severity_map, software_assessed, web_rows,
                exclude=exclude | more, explain=False, exploited=exploited)
        for p in pillars:
            for d in p["deductions"]:
                d["gain"] = rerun({d["code"]})["score"] - score
    by_type = {}
    for p in pillars:
        for d in p["deductions"]:
            by_type.setdefault(d["type"], (p["pillar"], []))[1].append(d)
    card["issue_types"] = []
    for t, (factor, items) in by_type.items():
        row = {"type": t, "factor": factor,
               "count": sum(d.get("count", 1) for d in items)}
        if explain:
            after = rerun({t})
            row.update(gain=after["score"] - score, grade_after=after["grade"])
        card["issue_types"].append(row)
    card["issue_types"].sort(key=lambda r: (-r.get("gain", 0), r["type"]))
    issues = []
    for p in pillars:
        for d in p["deductions"]:
            issue = {"pillar": p["pillar"], "type": d["type"], "label": d["label"],
                     "points": d["points"], "detail": d.get("detail", "")}
            if "gain" in d:
                issue["gain"] = d["gain"]
            issues.append(issue)
    issues.sort(key=lambda i: (-i.get("gain", 0), -i["points"]))
    card["issues"] = issues
    return card


def hosts_for_domain(domain, host):
    """True if `host` belongs to `domain` (exact or subdomain)."""
    d = str(domain or "").strip().lower().rstrip(".")
    h = str(host or "").strip().lower().rstrip(".")
    if not d or not h:
        return False
    return h == d or h.endswith("." + d)


def _tls_hosts(meta, cert_rows):
    """Hosts with a captured TLS certificate (inspected independently of the
    HTTP fingerprint, so a refused certificate still shows TLS is served)."""
    certs = (meta or {}).get("certificates")
    hosts = set(certs) if isinstance(certs, dict) else set()
    hosts.update(r.get("host") for r in cert_rows or () if isinstance(r, dict))
    return hosts


def build(domains, meta, software_rows=None, cert_rows=None,
          dns_results=None, severity_map=None, exclude=(), explain=True,
          exploited=()):
    """Build scorecards for every registered domain from a scan snapshot.

    Each row is attributed to the first matching registered domain, so a host
    is never counted twice when domains overlap (e.g. `example.com` and
    `www.example.com` both registered).
    """
    meta = meta or {}
    software_rows = software_rows or []
    cert_rows = cert_rows or []
    dns_results = dns_results or []
    services = meta.get("services") or {}
    if not isinstance(services, dict):
        services = {}

    dns_by_domain = {}
    for r in dns_results:
        if isinstance(r, dict) and r.get("domain"):
            dns_by_domain[str(r["domain"]).strip().lower()] = r

    domains = [str(d).strip().lower().rstrip(".")
               for d in (domains or []) if str(d).strip()]
    fingerprints = meta.get("fingerprints") or {}
    if not isinstance(fingerprints, dict):
        fingerprints = {}
    tls_hosts = _tls_hosts(meta, cert_rows)
    cards = []
    claimed = set()
    for dom in domains:
        sw = [r for r in software_rows
              if r.get("host") not in claimed and hosts_for_domain(dom, r.get("host"))]
        ct = [r for r in cert_rows
              if r.get("host") not in claimed and hosts_for_domain(dom, r.get("host"))]
        svc = [{"host": h, "open": (v or {}).get("open") or {}}
               for h, v in services.items()
               if h not in claimed and hosts_for_domain(dom, h)]
        # did any host on this domain actually get fingerprinted? that is what
        # separates "we looked and found no vulnerable software" from "we
        # never looked", which must not both score as clean
        fp_hosts = [h for h in fingerprints
                    if h not in claimed and hosts_for_domain(dom, h)]
        web = [dict(fingerprints[h], host=h, tls_seen=h in tls_hosts) for h in fp_hosts
               if isinstance(fingerprints[h], dict)]
        card = scorecard_for_domain(
            dom, software_rows=sw, cert_rows=ct,
            dns_result=dns_by_domain.get(dom),
            service_rows=(svc if svc else None),
            severity_map=severity_map,
            software_assessed=bool(fp_hosts),
            web_rows=web, exclude=exclude, explain=explain, exploited=exploited)
        cards.append(card)
        for r in sw:
            claimed.add(r.get("host"))
        for r in ct:
            claimed.add(r.get("host"))
        for row in svc:
            claimed.add(row["host"])
        for h in fp_hosts:
            claimed.add(h)
    return cards


def _dns_for_host(dns_result, host):
    """A domain's DNS verdict as it applies to one of its hosts.

    Email and DNS controls belong to the registered domain, so every host
    inherits them, except dangling-CNAME takeovers, which belong only to the
    host they were found on (one stale record must not cap its siblings).
    """
    if not isinstance(dns_result, dict) or dns_result.get("grade") in (None, "?"):
        return dns_result
    checks = dns_result.get("checks")
    if not isinstance(checks, dict):
        return dns_result
    takeover = [t for t in checks.get("takeover") or []
                if isinstance(t, dict) and str(t.get("host", "")).lower().rstrip(".") == host]
    if len(takeover) == len(checks.get("takeover") or []):
        return dns_result
    kept = dict(checks, takeover=takeover)
    score, grade = dns_posture._grade(kept, [])
    issues = [i for i in dns_result.get("issues") or []
              if i.get("check") != "takeover"
              or str(i.get("message", "")).lower().startswith(host + ":")]
    return dict(dns_result, checks=kept, score=score, grade=grade, issues=issues)


def _range_groups(meta, observed):
    """[(cidr, [ip, ...])] for the scan's IP-range addresses that were observed.

    Range addresses have no registered domain, so they are grouped under the
    first range containing them and get no email & DNS verdict (unknown).
    """
    nets = []
    for r in meta.get("ip_ranges") or []:
        try:
            nets.append((str(r), ipaddress.ip_network(str(r), strict=False)))
        except ValueError:
            continue
    groups = {cidr: [] for cidr, _ in nets}
    for h in sorted(set(meta.get("range_hosts") or []) & observed):
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            continue
        for cidr, net in nets:
            if ip in net:
                groups[cidr].append(h)
                break
    return [(cidr, ips) for cidr, ips in groups.items() if ips]


def build_hosts(domains, meta, software_rows=None, cert_rows=None, dns_results=None,
                severity_map=None, exploited=(), only=None, explain=False):
    """One card per observed host (subdomain): the same model applied to it.

    Every factor uses only that host's evidence, except email & DNS, which
    the host inherits from its registered domain (see _dns_for_host). Hosts
    are attributed to the first matching domain, as in build(). Cards carry
    `host` and `parent`; they are ordered critical exposure first, then
    weakest score, with hosts that have too little evidence to rate last. `only` restricts the build to one host
    (with `explain`, its deductions then carry exact host-score gains).
    """
    meta = meta or {}
    software_rows = software_rows or []
    cert_rows = cert_rows or []
    services = meta.get("services") if isinstance(meta.get("services"), dict) else {}
    fingerprints = meta.get("fingerprints") if isinstance(meta.get("fingerprints"), dict) else {}
    dns_by_domain = {str(r["domain"]).strip().lower(): r for r in dns_results or []
                     if isinstance(r, dict) and r.get("domain")}
    tls_hosts = _tls_hosts(meta, cert_rows)
    # a dangling CNAME is evidence about its host even when nothing else
    # answered there, and it is the one thing that host must not hide
    takeover_hosts = {str(t.get("host", "")).lower().rstrip(".")
                      for r in dns_by_domain.values()
                      for t in ((r.get("checks") or {}).get("takeover") or [])
                      if isinstance(t, dict)}
    observed = (set(fingerprints) | set(services) | tls_hosts | takeover_hosts
                | {r.get("host") for r in software_rows}) - {None, ""}
    domains = [str(d).strip().lower().rstrip(".") for d in (domains or []) if str(d).strip()]
    cards, claimed = [], set()
    groups = [(dom, sorted(h for h in observed if hosts_for_domain(dom, h))) for dom in domains]
    groups += _range_groups(meta, observed)
    for dom, members in groups:
        mine = [h for h in members if h not in claimed]
        claimed.update(mine)
        for h in mine:
            if only and h != only:
                continue
            fp = fingerprints.get(h)
            svc = services.get(h)
            card = scorecard_for_domain(
                h,
                software_rows=[r for r in software_rows if r.get("host") == h],
                cert_rows=[r for r in cert_rows if r.get("host") == h],
                dns_result=_dns_for_host(dns_by_domain.get(dom), h),
                service_rows=([{"host": h, "open": svc.get("open") or {}}]
                              if isinstance(svc, dict) else None),
                severity_map=severity_map,
                software_assessed=isinstance(fp, dict),
                web_rows=([dict(fp, host=h, tls_seen=h in tls_hosts)]
                          if isinstance(fp, dict) else []),
                explain=explain, exploited=exploited)
            if card["unknown"]:
                # too little evidence to score, but a takeover or compromised
                # CDN seen there is still critical exposure
                card["critical_exposure"] = any(
                    d["type"] in _CRITICAL_TYPES for p in card["pillars"] for d in p["deductions"])
            card.update(host=h, parent=dom, kind="range" if "/" in dom else "domain")
            cards.append(card)
    # critical exposure first (rated hosts with it are capped at 60 anyway),
    # then weakest score; hosts too thin to rate come last
    cards.sort(key=lambda c: (not c.get("critical_exposure"), c["unknown"], c["score"], c["host"]))
    return cards


def _worse(a, b):
    """Return the worse of two letter grades (with '?' handled)."""
    order = "ABCDF"
    if a not in order or b not in order:
        return a if a == b else "?"
    return a if order.index(a) >= order.index(b) else b


def summarize(cards):
    """Org-level rollup for the scorecard header.

    `average_grade` is deliberately conservative: it grades the average score
    and then applies any cap present on the underlying cards, so the header
    can never claim more confidence than the weakest card supports. Without
    that, a card capped to C for partial coverage could average back up into a
    B at the top line and contradict the cards underneath it.

    `factors` averages each factor over the domains where it was assessed;
    an unassessed factor is '?' rather than a borrowed number.
    """
    cards = cards or []
    graded = [c for c in cards if not c.get("unknown")]
    scores = [c["score"] for c in graded]
    grades = defaultdict(int)
    for c in cards:
        grades[c.get("grade") or "?"] += 1
    avg_score = int(round(sum(scores) / len(scores))) if scores else 0
    if graded:
        avg_grade = grade_for(avg_score)
        for card in graded:
            if card.get("coverage_cap"):
                avg_grade = _worse(avg_grade, card["grade"])
        if any(c.get("critical_cap") for c in graded):
            avg_grade = _worse(avg_grade, "D")
    else:
        avg_grade = "?"
    factors = []
    for key, weight in WEIGHTS.items():
        vals = [p["score"] for c in graded for p in c["pillars"]
                if p["pillar"] == key and not p["unknown"]]
        avg = int(round(sum(vals) / len(vals))) if vals else None
        factors.append({"factor": key, "label": PILLAR_LABELS[key], "weight": weight,
                        "score": avg, "grade": grade_for(avg) if vals else "?",
                        "assessed": len(vals)})
    return {
        "domains": len(cards),
        "assessed": len(graded),
        "average_score": avg_score,
        "worst_score": min(scores) if scores else 0,
        "average_grade": avg_grade,
        "grades": dict(sorted(grades.items())),
        "with_critical": sum(1 for c in cards if c.get("critical_exposure", c.get("critical_cap"))),
        "unknown": sum(1 for c in cards if c.get("unknown")),
        "factors": factors,
    }


def org_issues(cards, rebuild=None):
    """Issue types across every domain, worst first, from the issue catalog.

    `rebuild(exclude)` re-scores every domain with those issue types treated
    as fixed. The resulting `gain` is the change in the header average, so
    caps and the conservative header grade are honoured exactly.
    """
    agg = {}
    for c in cards or ():
        for t in c.get("issue_types") or ():
            info = ISSUE_TYPES.get(t["type"]) or _issue(
                t.get("factor", ""), "low", t["type"], "", "")
            row = agg.setdefault(t["type"], dict(info, type=t["type"], count=0,
                                                 domains=[]))
            row["count"] += t["count"]
            row["domains"].append({"domain": c["domain"], "count": t["count"],
                                   "gain": t.get("gain")})
    if rebuild is not None and agg:
        base = summarize(cards)["average_score"]
        for row in agg.values():
            after = summarize(rebuild({row["type"]}))
            row["gain"] = after["average_score"] - base
            row["grade_after"] = after["average_grade"]
    return sorted(agg.values(), key=lambda r: (
        -r.get("gain", 0), _SEVERITY_ORDER.get(r["severity"], 9), -r["count"], r["type"]))
