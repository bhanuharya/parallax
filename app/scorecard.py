"""scorecard.py — per-domain security scorecard over the asset inventories.

Rolls the three independent inventories into one verdict per domain:

  vulnerability   CVE-bearing software found on that domain's hosts
  certificates    expired / expiring / mismatched / untrusted TLS certs
  email_dns       SPF, DMARC, DKIM, DNSSEC, CAA, MTA-STS posture
  exposed         high-risk services reachable from the internet

Design rules, following risk.py and dns_posture.py:

  - DETERMINISTIC. Score is a pure function of the scan snapshot. Nothing is
    persisted here and no stored severity is mutated; the score is a separate,
    fully itemized field so an analyst or auditor can see exactly why one
    domain outranks another.

  - ITEMIZED. Every deduction is recorded as {code, label, points, detail}.
    A score without its arithmetic is an opinion; this is arithmetic.

  - UNKNOWN IS NOT GOOD. A pillar with no data for a domain (never scanned, no
    certs captured, resolver outage) is EXCLUDED from both numerator and
    denominator. A domain whose certificates were never inspected must not
    score as though it had clean certificates. When every pillar is unknown
    the grade is '?' and the score is 0 with `unknown: true`.

  - NOT DOUBLE-COUNTED. The exposed-services pillar looks only at reachable
    service ports. CVEs are scored once, in the vulnerability pillar.

  - CAPPED. A domain cannot buy back its grade with good hygiene elsewhere:
    confirmed critical exposure caps the total, mirroring how a dangling CNAME
    caps the DNS posture grade.
"""
from collections import defaultdict

# Pillar weights (sum to 100). Vulnerability exposure dominates because it is
# the thing that is actually exploitable on a host you already expose.
WEIGHTS = {
    "vulnerability": 40,
    "certificates": 25,
    "email_dns": 25,
    "exposed": 10,
}

PILLAR_LABELS = {
    "vulnerability": "Vulnerability exposure",
    "certificates": "Certificate hygiene",
    "email_dns": "Email & DNS posture",
    "exposed": "Exposed services",
}

_GRADE_BANDS = (("A", 90), ("B", 80), ("C", 70), ("D", 55), ("F", 0))

# Ports that should essentially never be reachable from the public internet.
# (port, points, label)
HIGH_RISK_PORTS = (
    (23, 4, "Telnet"),
    (445, 4, "SMB"),
    (3389, 4, "RDP"),
    (5900, 3, "VNC"),
    (2375, 4, "Docker API"),
    (2376, 4, "Docker API (TLS)"),
    (3306, 3, "MySQL"),
    (5432, 3, "PostgreSQL"),
    (1433, 3, "MSSQL"),
    (27017, 4, "MongoDB"),
    (6379, 4, "Redis"),
    (9200, 3, "Elasticsearch"),
    (11211, 3, "memcached"),
    (5984, 3, "CouchDB"),
)

# Vulnerability deductions by worst matched CVE severity. A vulnerable package
# is evidence, not proof of exploitability, so each is a bounded deduction
# rather than a zeroing.
_CVE_POINTS = {"CRITICAL": 12, "HIGH": 7, "MEDIUM": 3}
_CVE_POINTS_MAX = 34          # one host cannot consume the whole pillar

# Certificate deductions by issue type.
_CERT_POINTS = {
    "expired": 8,
    "untrusted chain": 5,
    "hostname mismatch": 6,
    "self-signed": 3,
    "expiring soon": 2,
}
_CERT_POINTS_MAX = 22


def grade_for(score):
    """Letter grade for a 0-100 score."""
    for grade, floor in _GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


def _deduction(code, label, points, detail=""):
    return {"code": code, "label": label, "points": int(points), "detail": str(detail)[:200]}


def _verdict(pillar, items, available=True, note=""):
    """Turn a pillar's deductions into a scored verdict."""
    max_points = WEIGHTS[pillar]
    if not available:
        return {
            "pillar": pillar, "label": PILLAR_LABELS[pillar],
            "max": max_points, "earned": None, "deductions": [],
            "unknown": True, "note": note or "no data",
        }
    lost = min(max_points, sum(i["points"] for i in items))
    return {
        "pillar": pillar, "label": PILLAR_LABELS[pillar],
        "max": max_points, "earned": max_points - lost,
        "deductions": items, "unknown": False, "note": note,
    }


# --------------------------------------------------------------------------
# pillar builders — each takes only pre-gathered rows
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


def vulnerability_pillar(software_rows, severity_map=None, assessed=True):
    """Deductions for CVE-bearing software on a domain's hosts.

    `software_rows` are inventory rows already filtered to this domain.
    `severity_map` maps CVE id -> severity; when a CVE is absent the row's
    worst severity is unknown and is treated as MEDIUM (the map only carries
    CRITICAL/HIGH entries, so an unknown id should not be scored as critical).

    `assessed` distinguishes the two cases that look identical from an empty
    row list: hosts were fingerprinted and simply disclosed no versioned
    software (we looked — clean), versus no host was fingerprinted at all (we
    did not look — unknown, which must not read as clean).
    """
    severity_map = severity_map or {}
    if not software_rows:
        if not assessed:
            return _verdict("vulnerability", [], available=False,
                            note="no hosts fingerprinted")
        return _verdict("vulnerability", [], available=True,
                        note="no versioned software disclosed")
    items = []
    total = 0
    # one deduction per vulnerable product row, bounded in aggregate
    for row in sorted(software_rows, key=lambda r: -r.get("cve_count", 0)):
        if not row.get("cve_count"):
            continue
        cves = row.get("related_cves") or []
        sev = _worst_severity(cves, severity_map) or "MEDIUM"
        pts = _CVE_POINTS.get(sev, 3)
        if total + pts > _CVE_POINTS_MAX:
            pts = max(0, _CVE_POINTS_MAX - total)
        if pts <= 0:
            break
        total += pts
        items.append(_deduction(
            "vuln:%s:%s" % (row.get("host"), row.get("product")),
            "%s %s on %s" % (row.get("product"), row.get("version") or "(no version)",
                             row.get("host")),
            pts, "%d CVE(s), worst %s" % (row.get("cve_count", 0), sev)))
    return _verdict("vulnerability", items,
                    note="%d of %d components carry CVEs"
                         % (sum(1 for r in software_rows if r.get("cve_count")),
                            len(software_rows)))


def certificate_pillar(cert_rows):
    """Deductions for certificate hygiene on a domain's hosts."""
    if not cert_rows:
        return _verdict("certificates", [], available=False,
                        note="no certificates captured")
    items = []
    total = 0
    for row in cert_rows:
        for issue in (row.get("issues") or []):
            pts = _CERT_POINTS.get(issue)
            if not pts:
                continue
            if total + pts > _CERT_POINTS_MAX:
                pts = max(0, _CERT_POINTS_MAX - total)
            if pts <= 0:
                break
            total += pts
            items.append(_deduction(
                "cert:%s:%s" % (row.get("host"), issue),
                "%s on %s" % (issue, row.get("host")), pts,
                row.get("not_after") or ""))
    ok = sum(1 for r in cert_rows if not r.get("issues"))
    return _verdict("certificates", items,
                    note="%d of %d certificates clean" % (ok, len(cert_rows)))


def email_dns_pillar(dns_result):
    """Deductions from the DNS posture verdict for the domain itself.

    Reuses dns_posture's 0-100 score rather than re-deriving it, so the
    scorecard and the posture panel can never disagree.
    """
    if not dns_result or dns_result.get("grade") in (None, "?"):
        return _verdict("email_dns", [], available=False,
                        note="DNS posture not assessed")
    base = float(dns_result.get("score") or 0)
    max_points = WEIGHTS["email_dns"]
    lost = int(round(max_points * (100.0 - base) / 100.0))
    items = []
    remaining = lost
    # attribute the loss to the individual failing checks so the panel is
    # actionable rather than just a number
    for issue in (dns_result.get("issues") or []):
        if remaining <= 0:
            break
        sev = issue.get("severity")
        share = {"HIGH": 8, "MEDIUM": 5, "LOW": 2}.get(sev, 1)
        share = min(share, remaining)
        remaining -= share
        items.append(_deduction(
            "dns:%s" % issue.get("check"),
            issue.get("message", "")[:120], share,
            issue.get("check", "")))
    if remaining > 0:
        items.append(_deduction("dns:other", "other posture gaps", remaining, ""))
    return _verdict("email_dns", items,
                    note="posture score %d/100" % int(base))


def exposed_pillar(service_rows):
    """Deductions for high-risk services reachable on a domain's hosts.

    `service_rows` is [{host, open: {port: name}}] for this domain's hosts.
    """
    if service_rows is None:
        return _verdict("exposed", [], available=False, note="no service scan")
    items = []
    for row in service_rows:
        open_ports = row.get("open") or {}
        for port, pts, label in HIGH_RISK_PORTS:
            if str(port) in {str(p) for p in open_ports}:
                items.append(_deduction(
                    "exposed:%s:%s" % (row.get("host"), port),
                    "%s (%s) reachable on %s" % (label, port, row.get("host")),
                    pts, ""))
    return _verdict("exposed", items,
                    note="%d host(s) probed" % len(service_rows))


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------
def scorecard_for_domain(domain, software_rows=None, cert_rows=None,
                         dns_result=None, service_rows=None,
                         severity_map=None, software_assessed=None):
    """Build one domain's scorecard from already-filtered rows.

    Returns {domain, score, grade, coverage, confidence, pillars[], issues[],
    unknown, critical_cap, coverage_cap}.

    `software_assessed` defaults to None meaning "infer": assessed when any
    fingerprint rows exist. It must be passed explicitly only when the caller
    knows the scan looked at hosts and found no versioned software — the
    default must never claim a domain was examined when nothing was supplied.

    `coverage` is the share of the total weight that could actually be
    assessed. It exists because excluding unknown pillars from the average —
    the right call, since an outage must not read as a finding — means a
    barely-examined domain could otherwise score 100. A grade is never issued
    above C when any pillar is missing.
    """
    if software_assessed is None:
        software_assessed = bool(software_rows)
    pillars = [
        vulnerability_pillar(software_rows or [], severity_map,
                             assessed=software_assessed),
        certificate_pillar(cert_rows or []),
        email_dns_pillar(dns_result),
        exposed_pillar(service_rows),
    ]
    known = [p for p in pillars if not p.get("unknown")]
    coverage = int(round(100.0 * sum(p["max"] for p in known) / sum(WEIGHTS.values())))
    # A card is "unknown" when essentially nothing was examined. The software
    # pillar can be marked assessed on empty input (we looked, nothing
    # disclosed), which alone would otherwise produce a confident 100 — so
    # require real coverage before calling a card assessed.
    if not known or coverage < 30:
        return {
            "domain": domain, "score": 0, "grade": "?",
            "coverage": coverage, "confidence": "none",
            "pillars": pillars, "issues": [], "unknown": True,
            "critical_cap": False, "coverage_cap": False,
        }
    earned = sum(p["earned"] for p in known)
    possible = sum(p["max"] for p in known)
    score = int(round(100.0 * earned / possible))

    # A confirmed critical CVE on a reachable host is a hard cap: clean
    # hygiene elsewhere must not launder it into a B.
    critical = any(d["code"].startswith("vuln:") and "CRITICAL" in d.get("detail", "")
                   for p in pillars for d in p["deductions"])
    capped = False
    if critical and score > 60:
        score = 60
        capped = True

    grade = grade_for(score)
    coverage_cap = False
    # A grade is a claim about the whole picture, so it cannot exceed what was
    # actually examined: with a major pillar missing (e.g. no software was ever
    # fingerprinted) the arithmetic may read 100 but the evidence does not
    # support an A. Tiers are deliberately blunt — this is a confidence
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

    issues = []
    for p in pillars:
        for d in p["deductions"]:
            issues.append({
                "pillar": p["pillar"],
                "label": d["label"],
                "points": d["points"],
                "detail": d.get("detail", ""),
            })
    issues.sort(key=lambda i: -i["points"])
    return {
        "domain": domain, "score": score, "grade": grade,
        "coverage": coverage, "confidence": confidence,
        "pillars": pillars, "issues": issues, "unknown": False,
        "critical_cap": capped, "coverage_cap": coverage_cap,
    }


def hosts_for_domain(domain, host):
    """True if `host` belongs to `domain` (exact or subdomain)."""
    d = str(domain or "").strip().lower().rstrip(".")
    h = str(host or "").strip().lower().rstrip(".")
    if not d or not h:
        return False
    return h == d or h.endswith("." + d)


def build(domains, meta, software_rows=None, cert_rows=None,
          dns_results=None, severity_map=None):
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
        card = scorecard_for_domain(
            dom, software_rows=sw, cert_rows=ct,
            dns_result=dns_by_domain.get(dom),
            service_rows=(svc if services else None),
            severity_map=severity_map,
            software_assessed=bool(fp_hosts))
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
        if any(c.get("coverage_cap") for c in graded) and avg_grade in ("A", "B"):
            avg_grade = "C"
        if any(c.get("critical_cap") for c in graded):
            avg_grade = _worse(avg_grade, "D")
    else:
        avg_grade = "?"
    return {
        "domains": len(cards),
        "assessed": len(graded),
        "average_score": avg_score,
        "worst_score": min(scores) if scores else 0,
        "average_grade": avg_grade,
        "grades": dict(sorted(grades.items())),
        "with_critical": sum(1 for c in cards if c.get("critical_cap")),
        "unknown": sum(1 for c in cards if c.get("unknown")),
    }
