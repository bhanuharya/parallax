"""Deterministic next steps and comparable scan history for external posture."""
import hashlib
import json
from scorecard import ISSUE_TYPES, hosts_for_domain, _web_responses

# 3: domain-local service coverage, page-level observation scope and corrected
# AngularJS advisory attribution. Earlier scores are not directly comparable.
# 4: hosts with a captured TLS certificate are no longer "served without
# HTTPS", and the client-side ssh-agent CVE-2023-38408 is withdrawn from
# server-banner matching (it produced false critical caps).
# 5: open ports count only when verified (a greeting, or a silent accept on a
# protocol that does not greet first, on a host that does not answer every
# port); load-balancer and firewall artifacts no longer deduct.
MODEL_VERSION = 5

_GUIDANCE = {
    "vulnerability": ("Verify and patch", "Verify the installed version and affected CVEs; upgrade to a supported, fixed release, then rescan."),
    "certificates": ("Repair TLS", "Renew or replace the certificate, check hostname coverage and the full trust chain, then rescan."),
    "email_dns": ("Review DNS policy", "Review the reported DNS control with the domain owner, validate the intended policy, then rescan."),
    "exposed": ("Restrict public access", "Confirm this service needs public access; restrict it to approved networks or a private access gateway, then rescan."),
    "application": ("Harden web responses", "Set the missing protection at the web server, application or CDN edge, then rescan."),
    "dependencies": ("Fix script sourcing", "Update how the page loads the dependency (version, source, integrity), then rescan."),
    "disclosure": ("Reduce disclosure", "Remove version details from response headers and markup at the server or proxy, then rescan."),
}


def action_plan(cards):
    """Scored priorities, not promises of score gains or proof of exploitation.

    `gain` is the exact rating change for that domain if the item alone is
    fixed under the current model; it is 0 while another item (such as a
    critical CVE cap) still bounds the score.
    """
    actions = []
    for card in cards:
        for pillar in card["pillars"]:
            key = pillar["pillar"]
            if pillar["unknown"]:
                actions.append({"domain": card["domain"], "pillar": key,
                                "priority": "Assess", "rank": 4, "points": 0, "gain": 0,
                                "title": "Assess " + pillar["label"].lower(),
                                "evidence": pillar["note"],
                                "next_step": "Run a scan and check collection failures. Missing evidence cannot establish a clean result."})
            for item in pillar["deductions"]:
                info = ISSUE_TYPES.get(item.get("type")) or {}
                critical = info.get("severity") == "critical"
                rank = 0 if critical else (1 if key in ("vulnerability", "exposed") else 2)
                verb, guidance = _GUIDANCE[key]
                actions.append({"domain": card["domain"], "pillar": key,
                                "type": item.get("type"),
                                "priority": "Urgent review" if rank == 0 else "Remediate",
                                "rank": rank, "points": item["points"],
                                "gain": item.get("gain", 0),
                                "title": verb + ": " + item["label"],
                                "evidence": item["detail"],
                                "next_step": info.get("fix") or guidance})
    actions.sort(key=lambda a: (a["rank"], -a["gain"], -a["points"], a["domain"], a["title"]))
    return actions


def snapshot(cards, meta):
    """Compact ledger record. Scope hashes detect changed observation coverage."""
    domains = []
    for card in cards:
        domain = card["domain"]
        basis = {key: sorted(h for h in (meta.get(key) if isinstance(meta.get(key), dict) else {})
                             if hosts_for_domain(domain, h))
                 for key in ("fingerprints", "certificates", "services")}
        basis["pillars"] = sorted(p["pillar"] for p in card["pillars"] if not p["unknown"])
        fingerprints = meta.get("fingerprints") or {}
        basis["versioned_products"] = sorted(
            (host, str(row.get("product", "")))
            for host, fp in (fingerprints.items() if isinstance(fingerprints, dict) else [])
            if hosts_for_domain(domain, host) and isinstance(fp, dict)
            for row in (fp.get("versions") or [])
            if isinstance(row, dict) and row.get("version"))
        web = _web_responses([
            dict(fp, host=host) for host, fp in
            (fingerprints.items() if isinstance(fingerprints, dict) else [])
            if hosts_for_domain(domain, host) and isinstance(fp, dict)])
        # A fingerprint can remain while document/asset collection fails.
        # Track observations per page, not just whether any page was read.
        basis["web_responses"] = sorted((r["host"], r["url"], str(r["code"])) for r in web)
        basis["asset_pages"] = sorted((r["host"], r["url"]) for r in web
                                      if isinstance(r.get("assets"), list))
        dns = meta.get("dns_posture")
        basis["dns_checks"] = sorted(
            name for row in (dns if isinstance(dns, list) else [])
            if isinstance(row, dict) and row.get("domain") == domain
            for name, check in (row.get("checks") or {}).items()
            if isinstance(check, dict) and not check.get("unknown"))
        domains.append({**{k: card[k] for k in ("domain", "score", "grade", "coverage", "unknown")},
                        "factors": {p["pillar"]: p.get("score") for p in card["pillars"]},
                        "scope": hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()})
    return {"version": MODEL_VERSION, "domains": sorted(domains, key=lambda d: d["domain"])}


def progress(current, events):
    """Compare with the preceding recorded scan, never subtract unknown scores."""
    scans = [e for e in events if isinstance(e, dict) and e.get("kind") == "scan"
             and isinstance(e.get("posture"), dict) and not (e.get("summary") or {}).get("error")]
    previous = scans[-1] if scans else None
    # The current persisted scan normally already has a ledger entry. Skip
    # precisely that entry, even when several consecutive scores are equal.
    if previous and previous["posture"] == current:
        previous = scans[-2] if len(scans) > 1 else None
    before = {d["domain"]: d for d in previous["posture"].get("domains", [])} if previous else {}
    changes = []
    for card in current["domains"]:
        old = before.get(card["domain"])
        reason = "Run another scan to establish a trend."
        comparable = False
        if old:
            if previous["posture"].get("version") != current["version"]:
                reason = "Scoring model changed; scores are not directly comparable."
            elif card["unknown"] or old["unknown"]:
                reason = "Insufficient evidence for a score comparison."
            elif card["scope"] != old.get("scope") or card["coverage"] != old.get("coverage"):
                reason = "Coverage changed; compare the evidence before interpreting the score."
            else:
                comparable = True
                reason = "Same observed hosts, versioned products and assessed controls as the preceding scan."
        changes.append({"domain": card["domain"], "comparable": comparable,
                        "delta": card["score"] - old["score"] if comparable else None,
                        "previous_grade": old.get("grade") if old else None,
                        "reason": reason})
    return {"changes": changes, "previous_at": previous.get("ts") if previous else None,
            "history": [{"at": e.get("ts", ""), **e["posture"]} for e in scans[-8:]],
            "trend": trend(scans, current["version"])}


def trend(scans, version=MODEL_VERSION, limit=24):
    """Recorded averages with explicit breaks at population/coverage changes.

    Unknown-only scans have no numeric point and interrupt continuity.
    Missing scope metadata never establishes comparability.
    """
    points = []
    previous_basis = None
    for e in scans:
        posture = e["posture"]
        if posture.get("version") != version:
            previous_basis = None
            continue
        domains = posture.get("domains", [])
        assessed = [d for d in domains if not d.get("unknown")]
        if not assessed:
            previous_basis = None
            continue
        basis = sorted((d["domain"], d.get("scope"), d.get("coverage"), bool(d.get("unknown")))
                       for d in domains)
        comparable = (previous_basis == basis and
                      all(d.get("scope") and d.get("coverage") is not None for d in domains))
        points.append({"at": e.get("ts", ""),
                       "score": int(round(sum(d["score"] for d in assessed) / float(len(assessed)))),
                       "domains": {d["domain"]: d["score"] for d in assessed},
                       "break_before": bool(points) and not comparable})
        previous_basis = basis
    return points[-limit:]
