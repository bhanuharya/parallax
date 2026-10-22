"""dns_posture.py — email-authentication and DNS-hygiene posture.

Answers the supply-chain questions that live in DNS rather than in HTTP:

  SPF    Is there an SPF record, is it syntactically sound, how many DNS
         lookups does it cost (RFC 7208 caps at 10), and does it end in a
         hard fail or a permissive `~all`/`?all`?
  DMARC  Is there a `_dmarc` policy, what is `p` (none/quarantine/reject),
         what percentage is enforced (`pct`), and is reporting configured?
  DKIM   Do common selectors publish a key (so mail can be authenticated)?
  DNSSEC Is the zone signed, and does the resolver validate the chain?
  CAA    Which CAs are authorised to issue for the zone? Absent CAA means any
         public CA may issue.
  MTA-STS / TLS-RPT  Is SMTP transport security advertised?
  Takeover  Does a CNAME point at a third-party service that no longer claims
         the name (the classic dangling-CNAME subdomain takeover)?

Design follows the rest of the codebase:
  - The analysis half is PURE: given already-fetched records it returns
    verdicts, so it is fully unit-testable offline and cannot do I/O.
  - The gather half is bounded and fail-open. Every lookup has a deadline, a
    hard query cap, and degrades to "unknown" rather than raising.
  - Only public DNS is queried. No payloads, no zone transfers, no guessing
    of private data.
  - Absence of a record is reported as a *posture gap* with the right
    severity, never as a confirmed compromise.
"""
import re

# RFC 7208 s4.6.4: the SPF evaluation may not exceed 10 DNS-querying
# mechanisms/modifiers. Over that, receivers return permerror.
SPF_LOOKUP_LIMIT = 10

# Selectors worth probing for DKIM. These are the widely deployed defaults;
# a missing key on all of them is a signal, not proof that DKIM is unused
# (an operator may use a custom selector we cannot guess).
COMMON_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "s1",
    "mail", "dkim", "smtp", "mandrill", "everlytickey1",
)

# Third-party services with a documented history of dangling-CNAME takeover:
# if a name points here and the target no longer resolves, anyone who can
# register the dangling name can serve content on the origin domain.
TAKEOVER_PROVIDERS = (
    ("s3.amazonaws.com", "Amazon S3 bucket"),
    ("s3-website", "Amazon S3 website endpoint"),
    ("cloudfront.net", "Amazon CloudFront distribution"),
    ("github.io", "GitHub Pages site"),
    ("herokuapp.com", "Heroku app"),
    ("herokudns.com", "Heroku DNS target"),
    ("azurewebsites.net", "Azure App Service"),
    ("cloudapp.azure.com", "Azure cloudapp"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("blob.core.windows.net", "Azure Blob storage"),
    ("fastly.net", "Fastly service"),
    ("pantheonsite.io", "Pantheon site"),
    ("myshopify.com", "Shopify store"),
    ("readme.io", "ReadMe site"),
    ("statuspage.io", "Statuspage"),
    ("surge.sh", "Surge site"),
    ("bitbucket.io", "Bitbucket Pages"),
    ("zendesk.com", "Zendesk instance"),
    ("freshdesk.com", "Freshdesk instance"),
    ("unbouncepages.com", "Unbounce page"),
    ("wpengine.com", "WP Engine site"),
    ("netlify.app", "Netlify site"),
    ("vercel.app", "Vercel project"),
    ("fly.dev", "Fly.io app"),
)

_SPF_MECH_RE = re.compile(
    r"^(?P<qual>[+\-~?])?(?P<name>all|include|a|mx|ptr|ip4|ip6|exists)"
    r"(?P<rest>[:=/].*)?$", re.I)
_DMARC_TAG_RE = re.compile(r"([a-z]+)\s*=\s*([^;]+)", re.I)
_VERSION_PREFIX = re.compile(r"^v\s*=\s*", re.I)


# --------------------------------------------------------------------------
# record normalisation helpers (pure)
# --------------------------------------------------------------------------
_QUOTED_CHUNK_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _txt_values(records):
    """Flatten TXT rdata into plain strings.

    A TXT record is a sequence of character-strings, and anything longer than
    255 bytes (most real SPF policies) is split across several. Stringifying
    such a record yields `'"part1" "part2"'`, so the quoted chunks must be
    extracted and concatenated — simply stripping the outer quotes silently
    corrupts the value. Backslash escapes are unescaped per RFC 1035.
    """
    out = []
    for rec in records or ():
        if rec is None:
            continue
        if isinstance(rec, (list, tuple)):
            # character-string chunks concatenate verbatim: stripping whitespace
            # between chunks would corrupt the record (SPF tokens run together)
            text = "".join(str(p).strip('"') for p in rec if p is not None)
        else:
            raw = str(rec).strip()
            chunks = _QUOTED_CHUNK_RE.findall(raw)
            if chunks:
                text = "".join(c.replace('\\"', '"') for c in chunks)
            else:
                # already-unquoted value (some resolvers) — use as-is
                text = raw
        text = text.strip()
        if text:
            out.append(text)
    return out


def spf_record(txt_values):
    """Return the SPF record among TXT values, or '' (last one wins per RFC)."""
    found = ""
    for v in _txt_values(txt_values):
        if v.lower().startswith("v=spf1"):
            found = v
    return found


def dmarc_record(txt_values):
    """Return the DMARC record among TXT values, or ''."""
    for v in _txt_values(txt_values):
        if v.lower().startswith("v=dmarc1"):
            return v
    return ""


def parse_dmarc(record):
    """Parse a DMARC record into {version, p, sp, pct, rua, ruf, adkim, aspf}."""
    if not record:
        return {}
    body = _VERSION_PREFIX.sub("", record.strip())
    tags = {}
    for key, value in _DMARC_TAG_RE.findall(body):
        tags[key.strip().lower()] = value.strip().strip('"')
    out = {}
    if tags.get("p"):
        out["p"] = tags["p"].lower()
    if tags.get("sp"):
        out["sp"] = tags["sp"].lower()
    if tags.get("pct"):
        try:
            out["pct"] = max(0, min(100, int(tags["pct"])))
        except (TypeError, ValueError):
            pass
    for k in ("rua", "ruf", "adkim", "aspf", "fo"):
        if tags.get(k):
            out[k] = tags[k]
    return out


def analyze_spf(record):
    """Score an SPF record.

    Returns {present, valid, mechanisms, lookups, all_qualifier, issues[],
    severity}. `lookups` counts the mechanisms that require an extra DNS
    query (include/a/mx/ptr/exists), which is what RFC 7208 caps.
    """
    record = (record or "").strip()
    if not record:
        return {"present": False, "missing": True, "valid": False,
                "mechanisms": [], "lookups": 0, "all_qualifier": None,
                "issues": ["no SPF record published"], "severity": "MEDIUM"}
    tokens = record.split()
    issues = []
    lookups = 0
    mechanisms = []
    all_qual = None
    if not tokens or tokens[0].lower() != "v=spf1":
        return {"present": True, "valid": False, "mechanisms": [],
                "lookups": 0, "all_qualifier": None,
                "issues": ["SPF record does not start with v=spf1"],
                "severity": "MEDIUM"}
    # a second "v=spf1" means the operator published two records by mistake;
    # receivers treat this as permerror, so mail may not be authenticated at all
    if sum(1 for t in tokens if t.lower() == "v=spf1") > 1:
        issues.append("record contains multiple v=spf1 tokens")
    for tok in tokens[1:]:
        if "=" in tok and not tok.startswith("+"):
            # modifiers (redirect=, exp=) do not count toward the limit except
            # redirect, which does cause an additional evaluation
            if tok.lower().startswith("redirect="):
                lookups += 1
            continue
        m = _SPF_MECH_RE.match(tok)
        if not m:
            issues.append("unrecognised mechanism: %s" % tok[:40])
            continue
        name = m.group("name").lower()
        mechanisms.append({
            "qualifier": m.group("qual") or "+",
            "name": name,
            "raw": tok[:80],
        })
        if name in ("include", "a", "mx", "ptr", "exists"):
            lookups += 1
        if name == "all":
            all_qual = m.group("qual") or "+"
    if all_qual is None:
        issues.append("no 'all' mechanism (no explicit default for unlisted senders)")
    elif all_qual in ("~", "?"):
        issues.append("permissive qualifier %sall (unlisted senders are not rejected)"
                      % all_qual)
    elif all_qual == "+":
        issues.append("'+all' authorises every sender — equivalent to no SPF")
    if lookups > SPF_LOOKUP_LIMIT:
        issues.append("%d DNS lookups exceeds the limit of %d (permerror at receivers)"
                      % (lookups, SPF_LOOKUP_LIMIT))
    if all_qual == "+":
        severity = "HIGH"
    elif issues:
        severity = "MEDIUM" if any("permerror" in i for i in issues) else "LOW"
    else:
        severity = None
    return {"present": True, "valid": True, "mechanisms": mechanisms,
            "lookups": lookups, "all_qualifier": all_qual,
            "issues": issues, "severity": severity}


def analyze_dmarc(record):
    """Score a DMARC policy. Missing DMARC means no alignment enforcement."""
    tags = parse_dmarc(record)
    if not tags:
        return {"present": False, "missing": True, "policy": None, "pct": None,
                "reporting": False, "issues": ["no DMARC record published"],
                "severity": "MEDIUM"}
    issues = []
    policy = tags.get("p")
    pct = tags.get("pct", 100)
    reporting = bool(tags.get("rua") or tags.get("ruf"))
    if policy == "none":
        issues.append("policy p=none monitors only — spoofed mail is still delivered")
    if policy in ("quarantine", "reject") and pct is not None and pct < 100:
        issues.append("policy applies to only %d%% of mail" % pct)
    if not reporting:
        issues.append("no rua/ruf reporting address (no visibility into failures)")
    if policy == "none":
        severity = "MEDIUM"
    elif issues:
        severity = "LOW"
    else:
        severity = None
    return {"present": True, "policy": policy, "pct": pct,
            "reporting": reporting, "issues": issues, "severity": severity}


def analyze_caa(records):
    """Summarise CAA. Absent CAA means any public CA may issue for the zone."""
    issues_ = [str(r).strip() for r in (records or ()) if str(r).strip()]
    if not issues_:
        return {"present": False, "missing": True, "issue": [], "iodef": [],
                "issues": ["no CAA record — any public CA may issue certificates"],
                "severity": "LOW"}
    issued, iodef = [], []
    for rec in issues_:
        parts = rec.split(None, 2)
        if len(parts) < 3:
            continue
        _flags, tag, value = parts[0], parts[1].strip('"').lower(), parts[2]
        value = value.strip().strip('"')
        if tag == "issue":
            issued.append(value)
        elif tag == "iodef":
            iodef.append(value)
    out = {"present": True, "issue": sorted(set(issued)), "iodef": iodef,
           "issues": [], "severity": None}
    if not issued:
        out["issues"].append("CAA present but no 'issue' property — no CA is authorised")
        out["severity"] = "MEDIUM"
    return out


def analyze_dnssec(enabled, has_ds):
    """Summarise DNSSEC state from what an external observer can actually see.

    Two observable facts: the zone publishes DNSKEY (signed) and the parent
    publishes DS (chain of trust established). Full cryptographic validation
    requires a validating resolver and the parent trust anchor, which this
    tool does not perform — so it reports the chain as *present*, never as
    "validated", and an unsigned zone is the only finding raised here.
    """
    if enabled is None:
        return {"enabled": None, "ds": None,
                "issues": [], "severity": None, "unknown": True}
    if not enabled:
        return {"enabled": False, "missing": True, "ds": bool(has_ds),
                "issues": ["zone is not DNSSEC-signed"], "severity": "LOW"}
    issues = []
    if not has_ds:
        issues.append("zone publishes DNSKEY but no DS at the parent — the "
                      "chain of trust is incomplete, so validators treat it as unsigned")
    return {"enabled": True, "ds": bool(has_ds), "issues": issues,
            "severity": "LOW" if issues else None}


def matching_takeover_provider(cname_target):
    """Return the provider label if `cname_target` belongs to a takeover-prone
    service, else ''."""
    target = str(cname_target or "").strip().lower().rstrip(".")
    for suffix, label in TAKEOVER_PROVIDERS:
        if target == suffix or target.endswith("." + suffix):
            return label
    return ""


def analyze_takeover(cname, target_resolves, had_dns_answer):
    """Classify a CNAME for dangling-target takeover risk.

    Only flags the deterministic case: the name is a CNAME to a takeover-prone
    provider AND the target no longer resolves while the origin previously
    answered. A CNAME to an unknown provider is not reported — guessing there
    produces the false positives that make takeover scanners untrustworthy.
    HTTP content checks are deliberately out of scope here.
    """
    target = str(cname or "").strip().rstrip(".")
    if not target:
        return None
    provider = matching_takeover_provider(target)
    if not provider:
        return None
    if target_resolves:
        return {"provider": provider, "target": target, "dangling": False,
                "issues": [], "severity": None}
    return {"provider": provider, "target": target, "dangling": True,
            "issues": ["CNAME points at an unclaimed %s target" % provider],
            "severity": "HIGH" if had_dns_answer is not False else "MEDIUM"}


# --------------------------------------------------------------------------
# aggregate posture for one domain
# --------------------------------------------------------------------------
def _unknown_check():
    """Verdict for a check that could not be determined (lookup failed)."""
    return {"present": False, "unknown": True, "issues": [], "severity": None}


def evaluate_domain(domain, snapshot):
    """Turn a gathered record snapshot into a posture verdict for one domain.

    `snapshot` is what the gather layer collected; every key is optional so a
    partial fetch (rate limit, timeout) still yields a useful, honest verdict.
    A key that is None (lookup failed) yields an "unknown" check — never a
    missing-record finding — and the check is excluded from scoring.
    Returns {domain, grade, score, checks{...}, issues[]}.
    """
    snapshot = snapshot or {}
    txt = snapshot.get("txt")
    dmarc_txt = snapshot.get("dmarc_txt")
    caa_raw = snapshot.get("caa")
    mta_raw = snapshot.get("mta_sts_txt")
    spf = _unknown_check() if txt is None else analyze_spf(spf_record(txt) or "")
    dmarc = _unknown_check() if dmarc_txt is None \
        else analyze_dmarc(dmarc_record(dmarc_txt) or "")
    caa = _unknown_check() if caa_raw is None else analyze_caa(caa_raw or [])
    mta_sts = _unknown_check() if mta_raw is None else _analyze_mta_sts(mta_raw)
    dkim = _analyze_dkim(snapshot.get("dkim") or {})
    dnssec = analyze_dnssec(snapshot.get("dnssec_enabled"),
                            snapshot.get("has_ds"))
    takeover = []
    for entry in (snapshot.get("cnames") or []):
        verdict = analyze_takeover(entry.get("cname"),
                                   entry.get("target_resolves"),
                                   entry.get("had_dns_answer"))
        if verdict and verdict.get("dangling"):
            verdict["host"] = entry.get("host")
            takeover.append(verdict)

    checks = {"spf": spf, "dmarc": dmarc, "dkim": dkim, "caa": caa,
              "dnssec": dnssec, "mta_sts": mta_sts, "takeover": takeover}
    issues = []
    for name in ("spf", "dmarc", "dkim", "caa", "dnssec", "mta_sts"):
        for msg in checks[name].get("issues") or []:
            issues.append({"check": name, "severity": checks[name].get("severity"),
                           "message": msg})
    for t in takeover:
        for msg in t.get("issues") or []:
            issues.append({"check": "takeover", "severity": t.get("severity"),
                           "message": "%s: %s" % (t.get("host"), msg)})

    score, grade = _grade(checks, issues)
    return {"domain": domain, "grade": grade, "score": score,
            "checks": checks, "issues": issues}


_DKIM_P_RE = re.compile(r"p\s*=\s*([^;]*)", re.I)


def dkim_selector_state(txt_values):
    """Classify one selector's _domainkey TXT into three states.

    True   — a usable public key (non-empty p=): mail can be signed
    False  — no record at all for this selector
    "null" — a record exists with an EMPTY p=: a deliberate null key that
             explicitly signs nothing (wildcard null keys are a known
             anti-spoofing posture — counting them as "key present" would
             overstate the domain's ability to sign mail)
    """
    vals = _txt_values(txt_values)
    if not vals:
        return False
    m = _DKIM_P_RE.search(vals[0])
    if m and m.group(1).strip():
        return True
    return "null"


def _analyze_dkim(found):
    """Summarise which common selectors publish a DKIM key.

    Absence is deliberately the weakest signal in the whole module: a provider
    may publish DKIM on a custom selector this tool cannot guess (Google, for
    one, signs with selectors that are not in any default list). So a miss is
    reported as informational context — never as a scoring penalty — and only
    the positive case is treated as a clean pass.
    """
    found = found or {}
    # only definitive probes count; a selector whose lookup was inconclusive
    # (resolver outage) is excluded rather than read as "no key"
    known = {k: v for k, v in found.items() if v is not None}
    if not known:
        return {"selectors_found": [], "unknown": True,
                "issues": [], "severity": None}
    present = sorted(k for k, v in known.items() if v is True)
    null = sorted(k for k, v in known.items() if v == "null")
    if present:
        return {"selectors_found": present, "null_selectors": null,
                "issues": [], "severity": None}
    issues = []
    if null:
        issues.append("null DKIM keys published (empty p=) — these selectors "
                      "explicitly sign nothing; custom selectors would not be "
                      "visible here")
    else:
        issues.append("no DKIM key on the common selectors probed (custom "
                      "selectors would not be visible here — corroborate against "
                      "the mail provider's documentation)")
    return {"selectors_found": [], "null_selectors": null,
            "issues": issues, "severity": "INFO",
            "informational": True}


def _analyze_mta_sts(txt_values):
    """Presence/shape of an MTA-STS policy record."""
    for v in _txt_values(txt_values):
        if v.lower().startswith("v=stsv1"):
            return {"present": True, "issues": [], "severity": None, "record": v}
    return {"present": False, "missing": True,
            "issues": ["no MTA-STS policy (SMTP transport security not advertised)"],
            "severity": "LOW"}


def _grade(checks, issues):
    """Deterministic 0-100 posture score and A-F grade, or (0, '?') when no
    check could be determined.

    Scoring is proportional over the checks that could actually be observed:
      - unknown (resolver unavailable): excluded from both numerator and
        denominator — an outage must not read as bad posture;
      - missing record: counts in the denominator, earns nothing — a missing
        SPF/DMARC is the primary spoofing enabler;
      - present but weak: partial credit (LOW 60%, MEDIUM 30%);
      - INFO: full credit — context, never a deficiency.
    Any dangling-CNAME takeover caps the score at 40% of possible.
    """
    weights = {"dmarc": 30, "spf": 25, "dkim": 15, "dnssec": 10,
               "caa": 10, "mta_sts": 10}
    earned = 0.0
    possible = 0
    for name, weight in weights.items():
        c = checks.get(name, {})
        if c.get("unknown"):
            continue
        possible += weight
        if c.get("missing"):
            continue
        sev = c.get("severity")
        if sev is None or sev == "INFO":
            earned += weight
        elif sev == "LOW":
            earned += weight * 0.6
        elif sev == "MEDIUM":
            earned += weight * 0.3
        # HIGH and above earns nothing
    if possible <= 0:
        return 0, "?"
    if checks.get("takeover"):
        earned = min(earned, possible * 0.4)
    score = int(round(100.0 * earned / possible))
    # takeover is a separate, severe signal: any dangling CNAME caps the grade
    if checks.get("takeover"):
        score = min(score, 40)
    score = int(round(score))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 55:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def summarize(results):
    """Aggregate per-domain verdicts for a dashboard header."""
    results = results or []
    grades = {}
    for r in results:
        grades[r.get("grade") or "?"] = grades.get(r.get("grade") or "?", 0) + 1
    return {
        "domains": len(results),
        "average_score": (int(round(sum(r.get("score", 0) for r in results)
                                    / len(results))) if results else 0),
        "grades": dict(sorted(grades.items())),
        "takeover_risks": sum(1 for r in results
                              if (r.get("checks", {}).get("takeover") or [])),
        "no_dmarc": sum(1 for r in results
                        if not r.get("checks", {}).get("dmarc", {}).get("present")),
        "no_spf": sum(1 for r in results
                      if not r.get("checks", {}).get("spf", {}).get("present")),
        "no_dnssec": sum(1 for r in results
                         if not r.get("checks", {}).get("dnssec", {}).get("enabled")),
    }


# ==========================================================================
# network gather layer — bounded, fail-open, public DNS only
# ==========================================================================
# Imported lazily so the pure analysis above (and its tests) never require the
# resolver library to be installed.
_RESOLVER = None
_RESOLVER_LOCK = None


def _resolver():
    """Shared resolver with a short deadline. Returns None if dnspython is
    unavailable — callers then report 'unknown' rather than failing a scan."""
    global _RESOLVER, _RESOLVER_LOCK
    if _RESOLVER is not None:
        return _RESOLVER or None
    import threading
    if _RESOLVER_LOCK is None:
        _RESOLVER_LOCK = threading.Lock()
    with _RESOLVER_LOCK:
        if _RESOLVER is not None:
            return _RESOLVER or None
        try:
            import dns.resolver
            r = dns.resolver.Resolver()
            r.lifetime = 8.0
            r.timeout = 5.0
            _RESOLVER = r
        except Exception:
            _RESOLVER = False
    return _RESOLVER or None


def _query(name, rtype):
    """One bounded DNS query. Returns a list of strings, [] for NoAnswer /
    NXDOMAIN, or None when the lookup could not be performed (so 'unknown' is
    distinguishable from 'absent' — the difference matters for findings)."""
    r = _resolver()
    if r is None:
        return None
    try:
        import dns.resolver
        answer = r.resolve(name, rtype, lifetime=8.0)
        return [str(x) for x in answer]
    except Exception as e:
        name_ = type(e).__name__
        if name_ in ("NXDOMAIN", "NoAnswer", "NoNameservers"):
            return []
        return None


def _resolve_target(name):
    """True/False if the name resolves; None when undeterminable."""
    r = _resolver()
    if r is None:
        return None
    try:
        r.resolve(name, "A", lifetime=6.0)
        return True
    except Exception as e:
        if type(e).__name__ in ("NXDOMAIN", "NoAnswer"):
            return False
        try:
            r.resolve(name, "AAAA", lifetime=6.0)
            return True
        except Exception as e2:
            if type(e2).__name__ in ("NXDOMAIN", "NoAnswer"):
                return False
        return None


def gather(domain, hosts=None, max_cname_hosts=25):
    """Collect the DNS records behind a posture verdict for one domain.

    Every lookup is optional and fail-open: a timeout or missing resolver
    yields None/[] and the verdict degrades to "unknown" for that check rather
    than aborting the scan. `hosts` is an optional list of already-discovered
    subdomains used for the CNAME/takeover probe (capped).
    """
    domain = str(domain or "").strip().lower().rstrip(".")
    if not domain:
        return {}
    snapshot = {"domain": domain}

    # None (lookup failed) is preserved — evaluate_domain turns it into an
    # "unknown" verdict. Collapsing it to [] here would misreport an outage
    # as "record absent", which is a finding we cannot stand behind.
    snapshot["txt"] = _query(domain, "TXT")
    snapshot["dmarc_txt"] = _query("_dmarc." + domain, "TXT")
    snapshot["mta_sts_txt"] = _query("_mta-sts." + domain, "TXT")
    snapshot["caa"] = _query(domain, "CAA")

    dkim = {}
    for sel in COMMON_DKIM_SELECTORS:
        vals = _query("%s._domainkey.%s" % (sel, domain), "TXT")
        # None means the lookup itself failed — kept distinct from a
        # definitive miss so an outage is not read as "no DKIM"; "null" marks
        # a published-but-empty key (signs nothing)
        dkim[sel] = None if vals is None else dkim_selector_state(vals)
    snapshot["dkim"] = dkim

    dnskey = _query(domain, "DNSKEY")
    ds = _query(domain, "DS")
    snapshot["dnssec_enabled"] = bool(dnskey) if dnskey is not None else None
    snapshot["has_ds"] = bool(ds) if ds is not None else None
    # A validating resolver returning DNSKEY+DS is the practical proxy for
    # "chain validates"; we cannot perform full validation without the parent
    # trust anchor, so this is reported as enabled+ds, not cryptographically
    # verified, and the analysis language reflects that.
    snapshot["dnssec_validated"] = bool(dnskey and ds) if dnskey is not None else None

    cnames = []
    seen = set()
    for host in (hosts or [])[:max_cname_hosts]:
        host = str(host or "").strip().lower().rstrip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        try:
            recs = _query(host, "CNAME")
        except Exception:
            recs = None
        if not recs:
            continue
        target = str(recs[0]).strip().rstrip(".")
        if not target or not matching_takeover_provider(target):
            continue
        cnames.append({
            "host": host,
            "cname": target,
            "target_resolves": _resolve_target(target),
            "had_dns_answer": True,
        })
    snapshot["cnames"] = cnames
    return snapshot


def assess(domain, hosts=None):
    """Gather + evaluate in one call. Always returns a verdict dict."""
    return evaluate_domain(domain, gather(domain, hosts=hosts))

