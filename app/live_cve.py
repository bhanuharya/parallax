"""live_cve.py — live vulnerability intel from cve.now for externally seen packages.

cve.now (https://cve.now) merges the CVE List, GitHub advisories, OSV, NVD,
EUVD, CISA KEV, EPSS and Exploit-DB into one entry per vulnerability, free
and without an API key. Two calls are used:

  /stack?p=npm:name@version,...&format=json
        vulnerabilities affecting the exact package versions the scan saw
  /api/v1/entries/<CVE>
        one entry, to add CVSS and exploitation status (CISA KEV,
        Exploit-DB) to CVEs the offline map matched on server software

Rules, matching NVD enrichment elsewhere in the app:
  - OPT-IN (CTI_CVE_NOW=1). Package names and versions leave the host, so an
    operator chooses this. No org name, domain or host is ever sent.
  - FAIL-OPEN. Any error leaves the offline result untouched and never fails
    a scan; a partial fetch is recorded as `complete: false`.
  - SCAN-TIME, NOT READ-TIME. Results are captured into scan meta, so a
    rating stays a pure function of its snapshot and page loads never wait
    on a third party. An explicit refresh action re-captures them.
  - BOUNDED. Package batches and per-CVE lookups are capped, responses are
    size-limited by the HTTP helper, and answers are cached on disk.
  - UNTRUSTED INPUT. Responses are reduced to a compact, typed record: ids
    are validated, free text is truncated, and nothing is rendered unescaped.
"""
import json
import os
import re
import threading
import time
from urllib.parse import quote

import cve_match

BASE = "https://cve.now"
_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$", re.I)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_BATCH = 10
_cache_lock = threading.Lock()


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def enabled():
    return os.environ.get("CTI_CVE_NOW", "").strip().lower() in ("1", "true", "yes", "on")


def _ttl():
    return _env_int("CTI_CVE_NOW_TTL", 21600)


def _cache_path():
    return os.path.join(cve_match._state_dir(), "cvenow_cache.json")


def _cache_load():
    try:
        with open(_cache_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _cache_store(entries):
    try:
        os.makedirs(cve_match._state_dir(), exist_ok=True)
        with _cache_lock:
            cache = _cache_load()
            cache.update(entries)
            # keep the file bounded: drop the oldest entries past 5000 keys
            if len(cache) > 5000:
                for k in sorted(cache, key=lambda k: cache[k].get("ts", 0))[:len(cache) - 5000]:
                    cache.pop(k, None)
            tmp = _cache_path() + ".tmp"
            with open(tmp, "w") as f:
                json.dump(cache, f)
            os.replace(tmp, _cache_path())
    except Exception:
        pass


def _get(path):
    data = cve_match._http_get_json(BASE + path, timeout=20,
                                    headers=["Accept: application/json"])
    return data if isinstance(data, dict) and data else None


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def _date(value):
    s = str(value or "")
    return s[:10] if _DATE_RE.match(s) else None


def _vkey(version):
    return cve_match._vkey(str(version or "")) or ()


def _fixed_for(entry, ecosystem, name, version):
    """The fixed version of the range that contains `version`, if any."""
    v = _vkey(version)
    for aff in entry.get("affected") or ():
        if not isinstance(aff, dict) or str(aff.get("package", "")).lower() != name.lower() \
                or str(aff.get("ecosystem", "")).lower() != ecosystem.lower():
            continue
        for rng in aff.get("ranges") or ():
            if not isinstance(rng, dict):
                continue
            lo = _vkey(rng.get("introduced") or "0")
            fixed, last = rng.get("fixed"), rng.get("lastAffected")
            if v < lo:
                continue
            if fixed and v >= _vkey(fixed):
                continue
            if last and v > _vkey(last):
                continue
            return str(fixed)[:40] if fixed else None
    return None


def compact(entry, package=None):
    """A typed, size-bounded record from one cve.now entry, or None."""
    if not isinstance(entry, dict):
        return None
    vid = str(entry.get("id") or "").strip()
    if not _ID_RE.match(vid):
        return None
    sev = entry.get("severity") if isinstance(entry.get("severity"), dict) else {}
    cvss = sev.get("cvss")
    cvss = float(cvss) if isinstance(cvss, (int, float)) and 0 <= cvss <= 10 else None
    stated = entry.get("statedSeverity")
    if isinstance(stated, dict):
        stated = stated.get("severity") or stated.get("label")
    stated = str(stated or "").strip().lower()
    stated = {"moderate": "medium"}.get(stated, stated)
    exp = entry.get("exploitation") if isinstance(entry.get("exploitation"), dict) else {}
    kev = exp.get("kev") if isinstance(exp.get("kev"), dict) else None
    out = {
        "id": vid.upper(),
        "aliases": [str(a).upper() for a in (entry.get("aliases") or [])
                    if _ID_RE.match(str(a))][:6],
        "title": str(entry.get("title") or "")[:200],
        "summary": str(entry.get("summary") or entry.get("originalDescription") or "")[:400],
        "cvss": cvss,
        "vector": str(sev.get("vector") or "")[:160],
        "stated": stated if stated in ("critical", "high", "medium", "low") else None,
        "kev": {"added": _date(kev.get("dateAdded")), "due": _date(kev.get("dueDate"))} if kev else None,
        "exploit_db": bool(exp.get("exploitDb")),
        "published": _date(entry.get("publishedAt")),
    }
    if package:
        eco, name, version = package
        out["fixed"] = _fixed_for(entry, eco, name, version)
    return out


def severity_of(record):
    """CRITICAL/HIGH/MEDIUM/LOW from live CVSS (or stated severity), else None."""
    cvss = (record or {}).get("cvss")
    if isinstance(cvss, (int, float)):
        if cvss >= 9:
            return "CRITICAL"
        if cvss >= 7:
            return "HIGH"
        if cvss >= 4:
            return "MEDIUM"
        if cvss > 0:
            return "LOW"
    stated = (record or {}).get("stated")
    return stated.upper() if stated else None


def package_key(ecosystem, name, version):
    return "%s:%s@%s" % (ecosystem, name, version)


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------
def lookup_packages(packages, now=None):
    """{package key: [compact records]} for (ecosystem, name, version) tuples.

    Returns (results, errors). Cached answers are reused within the TTL; the
    rest are queried in batches of _BATCH. A failed batch is simply absent
    from the results and counted in `errors`.
    """
    now = now or time.time()
    cache = _cache_load()
    results, todo, errors = {}, [], 0
    for pkg in packages:
        key = package_key(*pkg)
        hit = cache.get("pkg:" + key)
        if isinstance(hit, dict) and now - hit.get("ts", 0) < _ttl():
            results[key] = hit.get("data") or []
        else:
            todo.append(pkg)
    fresh = {}
    for i in range(0, len(todo), _BATCH):
        batch = todo[i:i + _BATCH]
        query = ",".join(package_key(*p) for p in batch)
        data = _get("/stack?format=json&p=" + quote(query, safe=":@/,"))
        if data is None or not isinstance(data.get("entries"), list):
            errors += 1
            continue
        found = {package_key(*p): [] for p in batch}
        by_name = {(p[0].lower(), p[1].lower(), p[2]): p for p in batch}
        for entry in data["entries"]:
            m = entry.get("matched") if isinstance(entry, dict) else None
            if not isinstance(m, dict):
                continue
            pkg = by_name.get((str(m.get("ecosystem", "")).lower(),
                               str(m.get("name", "")).lower(), str(m.get("version", ""))))
            rec = compact(entry, pkg) if pkg else None
            if rec:
                found[package_key(*pkg)].append(rec)
        for key, recs in found.items():
            results[key] = recs
            fresh["pkg:" + key] = {"ts": now, "data": recs}
    if fresh:
        _cache_store(fresh)
    return results, errors


def lookup_entries(ids, cap, now=None):
    """{id: compact record} for vulnerability ids, at most `cap` network calls."""
    now = now or time.time()
    cache = _cache_load()
    results, fresh, calls, errors = {}, {}, 0, 0
    for vid in ids:
        if not _ID_RE.match(str(vid)):
            continue
        hit = cache.get("id:" + vid)
        if isinstance(hit, dict) and now - hit.get("ts", 0) < _ttl():
            if hit.get("data"):
                results[vid] = hit["data"]
            continue
        if calls >= cap:
            continue
        calls += 1
        rec = compact(_get("/api/v1/entries/" + quote(vid)))
        if rec is None:
            errors += 1
            continue
        results[vid] = rec
        fresh["id:" + vid] = {"ts": now, "data": rec}
    if fresh:
        _cache_store(fresh)
    return results, errors


def observed_packages(fingerprints):
    """Exact-version packages seen on hosts that cve.now can match (npm)."""
    import dependencies
    seen = []
    for s in (fingerprints or {}).values():
        if not isinstance(s, dict):
            continue
        for v in s.get("versions") or ():
            if not isinstance(v, dict):
                continue
            name = dependencies.NPM_NAMES.get(str(v.get("product") or "").lower())
            version = str(v.get("version") or "")
            if name and re.match(r"^\d+\.\d+\.\d+([-.+][0-9A-Za-z.]+)?$", version):
                pkg = ("npm", name, version)
                if pkg not in seen:
                    seen.append(pkg)
    return seen


def collect(fingerprints, max_packages=None, max_lookups=None):
    """Live intel for one scan snapshot, in the shape stored at meta.live_cves.

    {source, fetched_at, complete, errors, packages: {key: [ids]},
     cves: {id: record}}. Never raises.
    """
    max_packages = max_packages or _env_int("CTI_CVE_NOW_MAX_PACKAGES", 60)
    max_lookups = max_lookups or _env_int("CTI_CVE_NOW_MAX_LOOKUPS", 30)
    out = {"source": "cve.now", "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "complete": True, "errors": 0, "packages": {}, "cves": {}}
    try:
        packages = observed_packages(fingerprints)
        if len(packages) > max_packages:
            packages, out["complete"] = packages[:max_packages], False
        found, errors = lookup_packages(packages)
        out["errors"] += errors
        for key, recs in found.items():
            out["packages"][key] = [r["id"] for r in recs]
            for r in recs:
                out["cves"].setdefault(r["id"], r)
        # server software matched offline: add CVSS and exploitation status
        offline = []
        for s in (fingerprints or {}).values():
            for m in cve_match.match_cves((s or {}).get("versions") or [], cap=50):
                if m["cve"] not in out["cves"] and m["cve"] not in offline:
                    offline.append(m["cve"])
        entries, errors = lookup_entries(offline, max_lookups)
        out["errors"] += errors
        out["cves"].update(entries)
        if len(entries) < len(offline) or out["errors"]:
            out["complete"] = False
    except Exception:
        out["complete"] = False
        out["errors"] += 1
    return out
