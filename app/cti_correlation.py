"""cti_correlation.py — derive a CTI correlation graph from org findings data.

Pure, deterministic, $0: reads an org's findings.json + baseline.txt
(from the data/orgs.json registry) and produces a graph of entities
(host, IP, CVE, brand/domain, severity-class) connected by shared-attribute
edges. No external calls, no secrets, no action.

Correlation axes:
  1. IP co-residency  — multiple hosts on the same IP (shared box / infra cluster)
  2. CVE fleet spread — same CVE hitting multiple hosts (shared remediation)
  3. Share of brand    — hosts grouped under their root domain (from org registry)
  4. Vuln-class        — findings sharing a category (e.g. all Pre-auth RCE)
  5. Confirmed status  — CONFIRMED / VERSION-CONFIRMED / clean triangulation
"""
import html as _html
import copy
import json, os, re, threading, time
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
# Project root (one level above app/); runtime data may live elsewhere.
BASE = os.path.dirname(BASE)
DATA_ROOT = os.path.abspath(os.path.expanduser(
    os.environ.get("CTI_DATA_DIR", os.path.join(BASE, "data"))))

# per-org data dirs live under <data-root>/orgs/<slug>
ORG_ROOT = os.path.join(DATA_ROOT, "orgs")

# canonical lifecycle status per finding.
# RESOLVED: the finding's evidence disappeared from the surface (retired by
# the reconciliation pass) or a renewed cert / fixed service was observed.
# It is set ONLY by the deterministic reconciliation logic, never by AI.
CANONICAL_STATUSES = ("OPEN", "IN_PROGRESS", "MITIGATED", "ACCEPTED_RISK", "RESOLVED")

# statuses the analyst owns outright — reconciliation never auto-changes them
ANALYST_OWNED_STATUSES = ("IN_PROGRESS", "MITIGATED", "ACCEPTED_RISK")

# Entity grouping is derived only from each registered org's configured domains.

DEFAULT_ORG = "sample"

_REGISTRY_FILE = os.path.join(DATA_ROOT, "orgs.json")


# entity types -> color (retro terminal palette)
NODE_COLORS = {
    "host":  "#50fa7b",   # green
    "ip":    "#8be9fd",   # cyan
    "cve":   "#ff5555",   # red
    "brand": "#bd93f9",   # purple
    "class": "#ffb86c",   # amber
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _load_registry():
    if not os.path.exists(_REGISTRY_FILE):
        return {}
    try:
        with open(_REGISTRY_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


#: slug -> {name, domains, findings, baseline} from data/orgs.json
REGISTRY = _load_registry()


def _reload_registry():
    """Re-read data/orgs.json (call after registering a new org)."""
    global REGISTRY
    REGISTRY = _load_registry()


def org_list():
    """[{slug, name, domains, ip_ranges}, ...] sorted by slug."""
    return [{"slug": slug, "name": (o.get("name") or slug),
             "domains": o.get("domains") or [],
             "ip_ranges": o.get("ip_ranges") or []}
            for slug, o in sorted(REGISTRY.items())]


def org_get(slug):
    """Registry entry for slug or None."""
    return REGISTRY.get(slug)


def _resolve_registry_path(value):
    """Resolve a registry path against DATA_ROOT.

    Existing registries may store paths as ``data/orgs/...``; newer external
    registries may use ``orgs/...``. Both resolve under the configured runtime
    data root. Absolute paths remain supported only when their canonical target
    stays beneath that root; symlink escapes are rejected.
    """
    if not value:
        return None
    value = os.path.expanduser(str(value))
    root = os.path.realpath(DATA_ROOT)
    if os.path.isabs(value):
        resolved = os.path.realpath(value)
        return resolved if os.path.commonpath([root, resolved]) == root else None
    norm = os.path.normpath(value)
    if norm == "data":
        norm = "."
    elif norm.startswith("data" + os.sep):
        norm = norm[len("data" + os.sep):]
    resolved = os.path.realpath(os.path.join(root, norm))
    if os.path.commonpath([root, resolved]) != root:
        return None
    return resolved


def _org_paths(org):
    """Return (findings_path, baseline_path) for a registered org.

    Returns (None, None) for unknown orgs — callers must verify org existence
    via org_get() before calling. This prevents legacy fallback data leakage.
    """
    entry = REGISTRY.get(org)
    if entry:
        fp = _resolve_registry_path(entry.get("findings"))
        bp = _resolve_registry_path(entry.get("baseline"))
        if fp:
            return fp, bp
    return None, None


def _norm_cves(v):
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip() and str(x).strip() != "None"]
    return [x.strip() for x in str(v).split(";") if x.strip() and x.strip() != "None"]


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_DATE_RE = re.compile(r"20\d\d-\d\d-\d\d")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_cves(v):
    """Return deduped real CVE IDs from a list/string value (ignores None /
    misconfiguration / placeholder text like 'CVE-... (CVSS 9.8)')."""
    if v is None:
        return []
    parts = v if isinstance(v, list) else [v]
    out, seen = [], set()
    for p in parts:
        for m in _CVE_RE.findall(str(p)):
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


def single_public_ip(v):
    """Return v if it is a single plausible public IPv4, else None.

    Skips invalid / private / reserved / loopback / link-local / CGNAT /
    multicast / placeholder / multi-IP values (e.g. 'multiple', '(GCS)',
    '10.0.0.1, 172.16.0.1').
    """
    s = str(v).strip() if v is not None else ""
    if not _IPV4_RE.match(s):
        return None
    a, b, c, d = s.split(".")
    a, b, c, d = int(a), int(b), int(c), int(d)
    if any(x > 255 for x in (a, b, c, d)):
        return None
    if a == 0 or a == 127 or a >= 224:
        return None
    if a == 10:
        return None
    if a == 172 and 16 <= b <= 31:
        return None
    if a == 192 and b == 168:
        return None
    if a == 169 and b == 254:
        return None
    if a == 100 and 64 <= b <= 127:
        return None
    return s


def load_meta_date(org=DEFAULT_ORG):
    """Return the org scan meta date (ISO 'YYYY-MM-DD') or None (cached)."""
    return _cached_org_data(org)[2]


def load_meta(org=DEFAULT_ORG):
    """Return the org's meta dict (cached, shared — treat as read-only)."""
    return _cached_org_data(org)[3] or {}


# --------------------------------------------------------------------------
# evidence enrichment + PII masking helpers
# --------------------------------------------------------------------------
# keys whose values are treated as PII / confidential and must be masked
_PII_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "apisecret",
    "email", "mail", "phone", "mobile", "accountno", "account_number", "card",
    "cardno", "card_number", "pan", "cvv", "cif", "login", "username", "userid",
    "userId", "user_id", "clientip", "client_ip", "dest_ip", "sourceip",
    "deviceid", "device_id", "sessionid", "session_id", "authorization", "auth",
    "firstname", "lastname", "middlename", "fullname", "ssn", "nik", "npwp",
    "createdby", "modifiedby", "realm", "adUser", "fullname",
}

# value-level masks for common PII shapes appearing inside any string
def _mask_email(v):
    return re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                  lambda m: m.group(0)[0:1] + "***@" + m.group(0).split("@")[1],
                  v)

def _mask_phone(v):
    # +62/08/number runs of >=8 digits -> keep country + area prefix, mask rest
    def repl(m):
        digits = m.group(0)
        if len(digits) <= 6:
            return "*" * len(digits)
        return digits[:4] + "*" * (len(digits) - 6) + digits[-2:]
    return re.sub(r"(?<![\d*])\d{8,}(?![\d*])", repl, v)

def _mask_big_number(v):
    # long digit runs (account/card/bank) -> keep first 2-3 + last 2, mask middle
    def repl(m):
        d = m.group(0)
        if len(d) <= 5:
            return d[0:1] + "*" * (len(d) - 1) if d else d
        return d[:2] + "*" * (len(d) - 4) + d[-2:]
    return re.sub(r"\d{6,}", repl, v)

def _mask_ip_in_text(v):
    # internal/private + full public IPs in prose -> mask the last 2 octets
    def repl(m):
        ip = m.group(0)
        parts = ip.split(".")
        if len(parts) != 4:
            return ip
        a, b = parts[0], parts[1]
        return f"{a}.{b}.*.*"
    # public IPs
    v = re.sub(r"(?<![0-9.])(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}(?!\d)",
               repl, v)
    return v

def _mask_value(key, value):
    """Mask a single value based on its key name / content. Key-insensitive."""
    k = key.lower().replace("_", "").replace("-", "")
    if value is None:
        return value
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    s = str(value)
    # direct PII-key match -> fully mask (keep 1st char + ***)
    if k in {x.lower().replace("_", "") for x in _PII_KEYS} and \
       len(s.strip()) > 0:
        if len(s) <= 2:
            return "***"
        return s[0] + "*" * min(len(s) - 1, 8)
    # content-level masks
    s = _mask_email(s)
    s = _mask_phone(s)
    s = _mask_big_number(s)
    s = _mask_ip_in_text(s)
    return s

def _mask_deep(obj, key="val"):
    """Recursively mask a nested structure of dict/list/str."""
    if isinstance(obj, dict):
        return {_mask_key(k): _mask_deep(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_deep(x, key) for x in obj]
    if isinstance(obj, str):
        return _mask_value(key, obj)
    return obj

def _mask_key(k):
    """Mask obviously-sensitive KEY names too (e.g. silver into sil***)."""
    return k

def _mask_finding_deep(nf):
    """Apply PII masking to a finding's human-readable fields in-place (copy)."""
    out = dict(nf)
    for field in ("description", "impact", "status", "discovery", "title",
                  "category", "remediation", "proof_chain", "reproduction_steps",
                  "topics_exposed", "evidence", "status_detail",
                  "ai_provenance", "ai_suggestions", "ai_impact", "ai_grading",
                  "status_history"):
        if field in out:
            out[field] = _mask_deep(out[field], field)
    return out

def enrich_finding_evidence(f):
    """Ensure finding has report-style reproduction_steps + evidence.commands.

    reproduction_steps: if missing, derive from proof_chain (real captured
    steps). evidence: if a dict and missing a 'commands' snapshot, build one
    from reproduction_steps as command->snippet pairs.
    """
    if not isinstance(f, dict):
        return f
    steps = f.get("reproduction_steps")
    pc = f.get("proof_chain")
    if not isinstance(steps, list) or not steps:
        if isinstance(pc, list) and pc:
            f["reproduction_steps"] = list(pc)
        else:
            f["reproduction_steps"] = []
    steps = f.get("reproduction_steps") or []
    ev = f.get("evidence")
    if isinstance(ev, dict) and "commands" not in ev and steps:
        ev["commands"] = {}
        for s in steps:
            label = str(s).split(" -> ")[0][:60]
            snippet = str(s)
            if " -> " in str(s):
                snippet = str(s).split(" -> ", 1)[1][:120]
            ev["commands"][label[:40]] = snippet
    return f


# --------------------------------------------------------------------------
# status lifecycle + history ledger
# --------------------------------------------------------------------------
def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _slug_from_org(org):
    if isinstance(org, str):
        return str(org).strip()
    return str((org or {}).get("slug") or "").strip()


def history_path(org):
    return os.path.join(ORG_ROOT, _slug_from_org(org), "history.json")


def canonical_status(f):
    """Derive the canonical lifecycle status from a finding's status string."""
    s = str(f.get("status", "") or "").strip()
    if not s:
        return "OPEN"
    u = s.upper()
    if u in CANONICAL_STATUSES:
        return u
    if "ACCEPTED" in u and "RISK" in u:
        return "ACCEPTED_RISK"
    if "IN_PROGRESS" in u or "IN PROGRESS" in u or "IN-PROGRESS" in u:
        return "IN_PROGRESS"
    if "MITIGATED" in u:
        return "MITIGATED"
    return "OPEN"


def _is_positive_status(s):
    u = str(s or "").upper()
    return ("SECURE" in u) or ("CLEAN" in u)


# --------------------------------------------------------------------------
# stable finding identity (reconciliation backbone)
# --------------------------------------------------------------------------
def _finding_port(f):
    """Best-effort explicit port for a finding (int or '')."""
    for cand in (f.get("port"), (f.get("evidence") or {}).get("port")
                 if isinstance(f.get("evidence"), dict) else None):
        try:
            p = int(cand)
            if 1 <= p <= 65535:
                return p
        except (TypeError, ValueError):
            continue
    return ""


def identity_key(f):
    """Stable, content-derived identity for a finding.

    identity_key = <family>|<target>|<signature>. It survives rescans (unlike
    the timestamped display id) and is the unit of observation tracking:
    present in scan -> last_seen refreshed; absent -> missing_streak++.
    """
    tgt = str(f.get("target", "")).strip().lower()
    src = str(f.get("source", "")).strip().lower()
    cat = str(f.get("category", "")).strip().lower()
    port = _finding_port(f)

    if src == "scan-tls":
        return f"tls|{tgt}|{port}"
    if src == "scan-login":
        return f"login|{tgt}|"
    if src == "scan-headers":
        return f"headers|{tgt}|"
    if src == "baseline-diff":
        port = f.get("port")
        return f"diff|{tgt}|{int(port) if port else 'host'}"
    if src == "scan-version":
        ev = f.get("evidence") or {}
        prods = ""
        if isinstance(ev, dict):
            vs = ev.get("versions") or []
            if isinstance(vs, list):
                prods = ",".join(sorted(str(v.get("product", "")) for v in vs
                                        if isinstance(v, dict)))[:120]
        return f"version|{tgt}|{prods}"
    if src == "scan-cve":
        cves = ",".join(sorted(str(c) for c in (f.get("related_cves") or [])))[:160]
        return f"cve|{tgt}|{cves or cat}"
    if src == "ai-assess":
        return f"ai|{tgt}|{cat}"
    if src == "scan-enum":
        return f"surface-enum|{tgt}|"
    if src == "scan-surface":
        return f"surface-web|{tgt}|{port}"
    if src == "scan-services":
        return f"surface-tcp|{tgt}|{port}"
    if src in ("cve-share", "ip-co-residency", "internetdb") or src.startswith("corr"):
        cves = ",".join(sorted(str(c) for c in (f.get("related_cves") or [])))[:160]
        sig = cves or cat
        return f"corr|{src}|{tgt}|{sig}"
    if src.startswith("ohack"):
        # URL-targeted external findings: host + normalized path + category
        target_url = str(f.get("evidence", {}).get("url", "") if isinstance(f.get("evidence"), dict) else "")
        path = target_url.split("://", 1)[-1].rstrip("/").lower()[:160]
        return f"ohack|{tgt}|{path}|{cat}"
    # generic fallback: mirrors the historical dedup semantics
    return f"{src or 'unknown'}|{tgt}|{cat}"


def ensure_identity(f):
    """In-place: backfill identity_key for legacy findings. Idempotent — an
    existing identity_key is trusted (analyst/tool continuity beats remapping)."""
    ik = str(f.get("identity_key", "")).strip()
    if not ik:
        f["identity_key"] = identity_key(f)
    return f["identity_key"]


def _extract_found_date(f, org, meta_date):
    for key in ("status", "status_detail", "discovery"):
        m = _DATE_RE.search(str(f.get(key, "")))
        if m:
            return m.group(0)
    if meta_date is None:
        meta_date = load_meta_date(org)
    return meta_date


def ensure_lifecycle(f, org=DEFAULT_ORG, meta_date=None):
    """In-place: initialize first_seen / last_seen / status_history if absent."""
    fd = f.get("found_date")
    if not fd:
        fd = _extract_found_date(f, org, meta_date)
    if not fd:
        fd = _now_iso()
    if not f.get("first_seen"):
        f["first_seen"] = fd
    if not f.get("last_seen"):
        f["last_seen"] = fd
    sh = f.get("status_history")
    if not isinstance(sh, list) or not sh:
        f["status_history"] = [{
            "at": fd, "from": "", "to": f.get("status", "OPEN"),
            "by": "scan", "note": "initial",
        }]


def migrate_finding(f, org=DEFAULT_ORG, meta_date=None):
    """In-place: migrate legacy descriptive status -> canonical status (preserve
    the original descriptive text in status_detail), set the positive flag for
    SECURE/CLEAN findings, and initialize lifecycle metadata. Idempotent."""
    raw = f.get("status")
    s = str(raw or "").strip()
    u = s.upper()
    if u in CANONICAL_STATUSES:
        f["status"] = u or "OPEN"
    else:
        if "status_detail" not in f and s:
            f["status_detail"] = s
        f["status"] = canonical_status(f)
    if _is_positive_status(s) and not f.get("positive"):
        f["positive"] = True
    ensure_lifecycle(f, org=org, meta_date=meta_date)


# --- snapshot diffing (new / resolved / changed vs prior run) ---
def build_snapshot(fs):
    """Return {finding_id: {severity, status}} using canonical status."""
    snap = {}
    for f in fs:
        fid = str(f.get("id", "")).strip()
        if not fid:
            continue
        snap[fid] = {
            "severity": str(f.get("severity", "")).upper(),
            "status": canonical_status(f),
        }
    return snap


def diff_snapshot(prev, cur):
    """Return (new_ids, resolved_ids, changed_ids)."""
    prev = prev if isinstance(prev, dict) else {}
    cur = cur if isinstance(cur, dict) else {}
    new = sorted(k for k in cur if k not in prev)
    resolved = sorted(k for k in prev if k not in cur)
    changed = sorted(k for k in cur if k in prev and prev[k] != cur[k])
    return new, resolved, changed


# --- append-only history ledger (per-org lock + atomic append) ---
def _append_history_locked(hp, event):
    events = []
    if os.path.exists(hp):
        try:
            with open(hp) as fh:
                d = json.load(fh)
            if isinstance(d, list):
                events = d
        except Exception:
            events = []
    events.append(event)
    _atomic_write_json(hp, events)


def append_history(org, event):
    """Append one event to data/orgs/<slug>/history.json (append-only array)."""
    slug = _slug_from_org(org)
    if not slug:
        return
    hp = history_path(slug)
    os.makedirs(os.path.dirname(hp), exist_ok=True)
    with _org_lock(slug):
        _append_history_locked(hp, event)


def load_history(org=DEFAULT_ORG):
    """Return the list of history events for an org ([] if none)."""
    hp = history_path(org)
    events = []
    if os.path.exists(hp):
        try:
            with open(hp) as fh:
                d = json.load(fh)
            if isinstance(d, list):
                events = d
        except Exception:
            events = []
    return events


def history_summary(events):
    by_kind = {}
    for e in events:
        k = str(e.get("kind", "?"))
        by_kind[k] = by_kind.get(k, 0) + 1
    return {"total": len(events), "by_kind": by_kind}


def record_event_and_snapshot(org, kind, mode=None, note=""):
    """Lock, compute diff vs meta.last_snapshot, append a history event, update
    last_snapshot, and atomically persist. Returns the event summary dict."""
    slug = _slug_from_org(org)
    if not slug:
        return None
    fp = org_findings_path(slug)
    lock = _org_lock(slug)
    with lock:
        data = {"findings": []}
        if fp and os.path.exists(fp):
            try:
                with open(fp) as fh:
                    d = json.load(fh)
                if isinstance(d, dict):
                    data = d
            except Exception:
                data = {"findings": []}
        meta = data.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        prev = meta.get("last_snapshot") or {}
        fs = data.get("findings") or []
        cur = build_snapshot(fs)
        new, resolved, changed = diff_snapshot(prev, cur)
        summary = {
            "subdomains": int(meta.get("subdomains", 0) or 0),
            "found": len(fs),
            "new": len(new),
            "resolved": len(resolved),
            "changed": len(changed),
        }
        event = {
            "ts": _now_iso(),
            "kind": kind,
            "mode": mode,
            "summary": summary,
            "note": note,
        }
        meta["last_snapshot"] = cur
        data["meta"] = meta
        if fp:
            _atomic_write_json(fp, data)
            invalidate_org_cache(slug)
        hp = history_path(slug)
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        _append_history_locked(hp, event)
        return summary


def _id_slug(s):
    return re.sub(r"[^a-z0-9-]+", "-", str(s).lower()).strip("-")[:32]


def _ai_merge(existing, af):
    """Merge AI fields into an existing finding without duplicating identity."""
    for k, v in af.items():
        if k in ("id", "status", "status_detail", "mode", "target", "title"):
            continue
        if v is None or v == "" or v == [] or v == {}:
            continue
        existing[k] = v
    existing["status_detail"] = "AI-ASSESSED"
    existing["mode"] = "ai"
    existing["status"] = "OPEN"
    existing["last_seen"] = _now_iso()


def persist_ai_findings(org, ai_findings):
    """Merge AI assessment findings into findings.json, deduped by target+title.

    New AI findings get status OPEN + status_detail AI-ASSESSED + mode ai;
    existing matches have AI fields merged in place. Per-org lock + atomic
    write. Returns the number of newly added records.
    """
    slug = _slug_from_org(org)
    if not slug:
        return 0
    fp = org_findings_path(slug)
    lock = _org_lock(slug)
    added = 0
    with lock:
        data = {"findings": []}
        if fp and os.path.exists(fp):
            try:
                with open(fp) as fh:
                    d = json.load(fh)
                if isinstance(d, dict):
                    data = d
            except Exception:
                data = {"findings": []}
        existing = data.get("findings") or []
        idx = {}
        for f in existing:
            key = (str(f.get("target", "")).strip().lower(),
                   str(f.get("title", "")).strip().lower())
            idx[key] = f
        seq = len(existing)
        for af in ai_findings:
            target = str(af.get("target", "")).strip()
            title = str(af.get("title", "")).strip()
            if not target or not title:
                continue
            key = (target.lower(), title.lower())
            if key in idx:
                _ai_merge(idx[key], af)
                continue
            seq += 1
            nf = dict(af)
            nf["id"] = "AI-" + _id_slug(slug) + "-" + str(seq)
            nf["status"] = "OPEN"
            nf["status_detail"] = "AI-ASSESSED"
            nf["mode"] = "ai"
            nf["severity"] = str(af.get("severity", "INFO")).upper()
            nf["related_cves"] = [str(c) for c in (af.get("related_cves") or [])
                                  if isinstance(c, str) and str(c).strip()]
            ensure_lifecycle(nf, org=slug, meta_date=None)
            existing.append(nf)
            idx[key] = nf
            added += 1
        data["findings"] = existing
        if fp:
            _atomic_write_json(fp, data)
            invalidate_org_cache(slug)
    return added


def set_finding_status(org, id_, new_status, note=""):
    """Token-gated mutation helper: update a finding's canonical status, append
    status_history, and log a status_change history event. Returns (finding, err).
    """
    slug = _slug_from_org(org)
    if new_status not in CANONICAL_STATUSES:
        return None, "invalid status"
    fp = org_findings_path(slug)
    if not fp or not os.path.exists(fp):
        return None, "not found"
    lock = _org_lock(slug)
    with lock:
        data = {"findings": []}
        try:
            with open(fp) as fh:
                d = json.load(fh)
            if isinstance(d, dict):
                data = d
        except Exception:
            data = {"findings": []}
        fs = data.get("findings") or []
        target = None
        for f in fs:
            if str(f.get("id")) == str(id_):
                target = f
                break
        if target is None:
            return None, "not found"
        migrate_finding(target, org=slug)
        old = str(target.get("status", "OPEN"))
        now = _now_iso()
        target["status_history"].append({
            "at": now, "from": old, "to": new_status, "by": "user", "note": note,
        })
        target["status"] = new_status
        target["last_seen"] = now
        _atomic_write_json(fp, data)
        invalidate_org_cache(slug)
        event = {
            "ts": now,
            "kind": "status_change",
            "mode": None,
            "summary": {"subdomains": 0, "found": len(fs),
                        "new": 0, "resolved": 0, "changed": 1},
            "note": "%s: %s -> %s" % (id_, old, new_status),
        }
        hp = history_path(slug)
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        _append_history_locked(hp, event)
        return target, None


def add_finding_comment(org, id_, note, by=""):
    """Append one analyst feedback/comment to a finding (token-gated helper).

    Stored as finding["feedback"] = [{at, by, note}, ...] (capped to the most
    recent 50 entries). The scanner's AI triage pass later reads the latest
    feedback per host and weighs it on the next `mode=ai` scan.
    Returns (finding, err).
    """
    slug = _slug_from_org(org)
    note = (note or "").strip()
    if not note:
        return None, "empty note"
    note = note[:2000]
    by = (by or "").strip()[:60] or "analyst"
    fp = org_findings_path(slug)
    if not fp or not os.path.exists(fp):
        return None, "not found"
    lock = _org_lock(slug)
    with lock:
        data = {"findings": []}
        try:
            with open(fp) as fh:
                d = json.load(fh)
            if isinstance(d, dict):
                data = d
        except Exception:
            data = {"findings": []}
        fs = data.get("findings") or []
        target = None
        for f in fs:
            if str(f.get("id")) == str(id_):
                target = f
                break
        if target is None:
            return None, "not found"
        migrate_finding(target, org=slug)
        fb = target.get("feedback")
        if not isinstance(fb, list):
            fb = []
        fb.append({"at": _now_iso(), "by": by, "note": note})
        target["feedback"] = fb[-50:]
        _atomic_write_json(fp, data)
        invalidate_org_cache(slug)
        hp = history_path(slug)
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        _append_history_locked(hp, {
            "ts": _now_iso(),
            "kind": "comment",
            "mode": None,
            "summary": {"found": len(fs)},
            "note": "comment on %s: %s" % (id_, note[:120]),
        })
        return target, None


def normalize_finding(f, org=DEFAULT_ORG, meta_date=None):
    """Return a copy of `f` enriched with derived fields.

    Adds: found_date (first ISO date in status/discovery, else org meta date,
    else None), tier (CONFIRMED / CORRELATED / OTHER from status), cve_links
    (canonical NVD links for real CVEs only), shodan_link and internetdb_link
    (when a single plausible public IP is present).

    Evidence enrichment + PII masking (always applies to stored/displayed data):
      - reproduction_steps: built from proof_chain when the finding has one but
        no reproduction_steps yet (so every finding gets the report-style
        numbered command/step list).
      - commands snapshot: added to evidence from the reproduction steps
        (command -> snippet pairs) when evidence lacks one.
      - PII masking: any PII/confidential values in evidence, description,
        proof_chain, etc. are masked (never raw).
    """
    nf = dict(f)
    if meta_date is None:
        meta_date = load_meta_date(org)
    nf["found_date"] = _extract_found_date(f, org, meta_date)

    # canonical status + status_detail preservation + lifecycle metadata
    migrate_finding(nf, org=org, meta_date=meta_date)

    st = str(nf.get("status", "")).upper()
    sd = str(nf.get("status_detail", "")).upper()
    if "AI-ASSESSED" in sd:
        tier = "AI"
    elif "CONFIRMED" in sd:
        tier = "CONFIRMED"
    elif "CORRELATED" in sd or "CORRELATED" in st:
        tier = "CORRELATED"
    else:
        tier = "OTHER"
    nf["tier"] = tier

    nf["cve_links"] = ["https://nvd.nist.gov/vuln/detail/" + c
                       for c in extract_cves(f.get("related_cves"))]
    ip = single_public_ip(f.get("ip"))
    nf["shodan_link"] = "https://www.shodan.io/host/" + ip if ip else None
    nf["internetdb_link"] = "https://internetdb.shodan.io/" + ip if ip else None

    # --- evidence enrichment (reproduction steps from proof chain) ---
    enrich_finding_evidence(nf)

    # --- PII / confidential masking on all displayed textual content ---
    nf = _mask_finding_deep(nf)
    return nf


_SUMMARY_MAX = 240


def _list_summary(description):
    """Masked one-paragraph description for list cards, capped for payload size."""
    if not description:
        return None
    s = " ".join(str(description).split())
    # AI findings store the model's reason as a JSON-quoted string
    if s.startswith('"'):
        s = s[1:].removesuffix('"')
    s = _mask_value("description", s)
    if len(s) > _SUMMARY_MAX:
        s = s[:_SUMMARY_MAX].rsplit(" ", 1)[0].rstrip(",;:") + "…"
    return s or None


def normalize_finding_light(f, org=DEFAULT_ORG, meta_date=None):
    """Lightweight list-view normalization (small payload, no deep PII scan).

    Returns only the fields the findings list / graph summaries need, with
    masking applied to the short display strings. Heavy evidence fields are
    omitted so large orgs stay fast; /api/findings/{id} still returns the full
    masked detail.
    """
    nf = dict(f)
    if meta_date is None:
        meta_date = load_meta_date(org)
    nf["found_date"] = _extract_found_date(f, org, meta_date)
    migrate_finding(nf, org=org, meta_date=meta_date)

    st = str(nf.get("status", "")).upper()
    sd = str(nf.get("status_detail", "")).upper()
    if "AI-ASSESSED" in sd:
        tier = "AI"
    elif "CONFIRMED" in sd:
        tier = "CONFIRMED"
    elif "CORRELATED" in sd or "CORRELATED" in st:
        tier = "CORRELATED"
    else:
        tier = "OTHER"

    cves = extract_cves(f.get("related_cves"))
    ip = single_public_ip(f.get("ip"))
    prov = nf.get("provenance")
    confidence = prov.get("confidence") if isinstance(prov, dict) else None
    return {
        "id": nf.get("id"),
        "title": _mask_value("title", nf.get("title")),
        "severity": nf.get("severity"),
        "category": _mask_value("category", nf.get("category")),
        "status": nf.get("status"),
        "status_detail": _mask_value("status_detail", nf.get("status_detail")),
        "positive": bool(nf.get("positive")),
        "tier": tier,
        "confidence": confidence,
        "target": nf.get("target"),
        "ip": nf.get("ip"),
        "port": nf.get("port"),
        "summary": _list_summary(nf.get("description")),
        "found_date": nf.get("found_date"),
        "first_seen": nf.get("first_seen"),
        "last_seen": nf.get("last_seen"),
        "related_cves": f.get("related_cves"),
        "cve_links": ["https://nvd.nist.gov/vuln/detail/" + c for c in cves],
        "shodan_link": "https://www.shodan.io/host/" + ip if ip else None,
        "internetdb_link": "https://internetdb.shodan.io/" + ip if ip else None,
    }


# --------------------------------------------------------------------------
# persistence (per-org lock + atomic write + dedup)
# --------------------------------------------------------------------------
_locks_guard = threading.Lock()
_org_locks = {}


def _org_lock(slug):
    with _locks_guard:
        if slug not in _org_locks:
            _org_locks[slug] = threading.Lock()
        return _org_locks[slug]


def org_findings_path(org):
    """Absolute path to the org's findings.json (registered orgs only)."""
    fp, _ = _org_paths(org)
    return fp


def _atomic_write_bytes(path, data, mode=0o600):
    """Atomic durable file write: unique temp name in the target dir,
    flushed+fsynced before replace, restrictive permissions."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = os.path.join(d, ".%s.tmp.%d.%d" % (os.path.basename(path), os.getpid(),
                                             threading.get_ident()))
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_json(path, data):
    _atomic_write_bytes(path, (json.dumps(data, indent=2) + "\n").encode("utf-8"))


def _atomic_write_text(path, text):
    _atomic_write_bytes(path, text.encode("utf-8"))


def migrate_data_permissions():
    """One-time best-effort tightening of runtime data files: 0600 files,
    0700 dirs under DATA_ROOT/orgs plus top-level json/log artifacts.
    Called at app startup; safe to run repeatedly."""
    changed = 0
    roots = [os.path.join(DATA_ROOT, "orgs")]
    for name in ("orgs.json",):
        p = os.path.join(DATA_ROOT, name)
        if os.path.isfile(p):
            roots.append(p)
    for root in roots:
        if os.path.isdir(root):
            for cur, dirs, files in os.walk(root):
                for dname in dirs:
                    try:
                        p = os.path.join(cur, dname)
                        os.chmod(p, 0o700)
                        changed += 1
                    except OSError:
                        pass
                for fname in files:
                    if fname.startswith("."):
                        continue
                    try:
                        p = os.path.join(cur, fname)
                        os.chmod(p, 0o600)
                        changed += 1
                    except OSError:
                        pass
        elif os.path.isfile(root):
            try:
                os.chmod(root, 0o600)
                changed += 1
            except OSError:
                pass
    return changed


def _dedup_key(f):
    return "|".join([
        str(f.get("target", "")).strip().lower(),
        str(f.get("category", "")).strip().lower(),
        str(f.get("source", "")).strip().lower(),
    ])


def persist_correlated(org, new_findings, report=None):
    """Append deduplicated correlated findings to the org findings file.

    Existing findings are always preserved; only new ones (by stable
    target+category+source key) are appended. Write is atomic (tmp + replace)
    and guarded by a per-org lock. Returns the number of newly added records.
    """
    slug = org if isinstance(org, str) else str(org.get("slug") or org)
    fp = org_findings_path(slug)
    lock = _org_lock(slug)
    with lock:
        data = {"findings": []}
        if fp and os.path.exists(fp):
            try:
                with open(fp) as f:
                    d = json.load(f)
                if isinstance(d, dict):
                    data = d
            except Exception:
                data = {"findings": []}
        existing = data.get("findings") or []
        keys = {_dedup_key(f) for f in existing}
        added = 0
        for nf in new_findings:
            k = _dedup_key(nf)
            if k in keys:
                continue
            keys.add(k)
            existing.append(nf)
            added += 1
        data["findings"] = existing
        if report is not None:
            meta = data.get("meta")
            if not isinstance(meta, dict):
                meta = {}
            meta["correlation"] = report
            data["meta"] = meta
        if fp:
            _atomic_write_json(fp, data)
            invalidate_org_cache(slug)
    return added


def correlation_report(org=DEFAULT_ORG):
    """Return the latest correlation report stored in meta, or None."""
    fp = org_findings_path(org)
    if fp and os.path.exists(fp):
        try:
            with open(fp) as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("meta"), dict):
                return d["meta"].get("correlation")
        except Exception:
            pass
    return None


def _root_domain(host, domains=None):
    h = str(host).strip().lower().rstrip(".")
    roots = [str(d).strip().lower().rstrip(".")
             for d in (domains or []) if str(d).strip()]
    # No organization-specific fallback: grouping comes only from registry scope.
    # strip leading labels down to registrable-ish domain for the org's roots
    for root in roots:
        if h == root or h.endswith("." + root):
            return root
    # raw IP
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
        return "raw-ip"
    return "other"


# --- read-through cache for org files (findings/baseline/meta date) ---
_DATA_CACHE = {}
_DATA_CACHE_LOCK = threading.Lock()
_DATA_CACHE_TTL = 15.0  # seconds


def _read_org_files(org):
    fs, baseline, meta_date, meta = [], [], None, {}
    findings_path, baseline_path = _org_paths(org)
    if findings_path and os.path.exists(findings_path):
        try:
            with open(findings_path) as f:
                d = json.load(f)
            if isinstance(d, dict):
                fs = d.get("findings") or []
                meta = d.get("meta")
                if isinstance(meta, dict):
                    m = _DATE_RE.search(str(meta.get("date") or meta.get("scan_date") or ""))
                    if m:
                        meta_date = m.group(0)
                else:
                    meta = {}
        except Exception:
            fs = []
    if baseline_path and os.path.exists(baseline_path):
        try:
            with open(baseline_path) as f:
                baseline = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception:
            baseline = []
    return fs, baseline, meta_date, meta


def _cached_org_data(org):
    """Return (findings, baseline, meta_date) using a small TTL cache.

    The lock is held across read-and-store so a reader that misses the cache
    cannot interleave with a writer's invalidate and re-cache *stale* file
    content after the invalidation (the classic stale-after-write race).
    File reads under the lock are short (local disk, small JSON).
    """
    now = time.time()
    with _DATA_CACHE_LOCK:
        entry = _DATA_CACHE.get(org)
        if entry and now - entry.get("ts", 0) < _DATA_CACHE_TTL:
            return entry["data"]
        # read while holding the lock: an invalidate_org_cache() from a writer
        # either happens fully before our store (we then read fresh files) or
        # fully after (our fresh entry is dropped and the next read re-reads).
        data = _read_org_files(org)
        _DATA_CACHE[org] = {"data": data, "ts": time.time()}
        return data


def invalidate_org_cache(org):
    """Drop the cached read-through data for an org (call after file writes)."""
    with _DATA_CACHE_LOCK:
        _DATA_CACHE.pop(org, None)


def load_data(org=DEFAULT_ORG):
    """Return (findings, baseline) for an org (read-through cache).

    Return independent copies, including nested finding fields. Callers
    mutate findings during enrichment and must never alter shared cached data.
    """
    fs, baseline, _, _ = _cached_org_data(org)
    return copy.deepcopy(fs or []), copy.deepcopy(baseline or [])


# --- reusable in-memory builders (for aggregate request reuse) ---
def summary_from_data(fs, baseline):
    """Build summary payload from in-memory findings/baseline without re-reading files.

    Live-surface semantics: RESOLVED findings (evidence gone, retired by the
    reconciliation pass) are excluded from findings_total/severity so KPIs
    cannot inflate forever; their count is exposed separately."""
    sev = defaultdict(int)
    live = 0
    resolved = 0
    for f in (fs or []):
        if canonical_status(f) == "RESOLVED":
            resolved += 1
            continue
        live += 1
        sev[str(f.get("severity", "INFO")).upper()] += 1
    bl = baseline if isinstance(baseline, list) else []
    return {"findings_total": live, "resolved_total": resolved,
            "severity": dict(sev), "baseline": len(bl)}


def fleet_spread_from_data(fs):
    """CVE fleet spread from in-memory findings."""
    cve2hosts = defaultdict(set)
    for f in (fs or []):
        for c in _norm_cves(f.get("related_cves")):
            cve2hosts[c].add(str(f.get("target", "")))
    return [{"cve": c, "hosts": sorted(hs)} for c, hs in sorted(cve2hosts.items(), key=lambda x: -len(x[1]))]


def ip_sharing_from_data(fs):
    """IP co-residency from in-memory findings."""
    ip2hosts = defaultdict(set)
    for f in (fs or []):
        ip, tgt = str(f.get("ip", "")).strip(), str(f.get("target", "")).strip()
        if ip and ip != "None" and tgt:
            ip2hosts[ip].add(tgt)
    return [{"ip": ip, "hosts": sorted(hs)} for ip, hs in sorted(ip2hosts.items(), key=lambda x: -len(x[1]))]


def certificates_from_meta(meta):
    """Certificate inventory rows from scan meta, worst-first.

    Covers every inspected host (healthy certs included), so the dashboard can
    answer "what certificates do we have and when do they expire" rather than
    only listing the ones that already produced a finding. Sorted by urgency:
    expired, then days remaining ascending, then hostname mismatch.

    `meta` is the org findings file's meta dict. Certificate data lives under
    meta.certificates; findings are joined in by target so each row carries
    the finding id a user can click through to.
    """
    meta = meta or {}
    certs = meta.get("certificates") or {}
    if not isinstance(certs, dict):
        return []
    rows = []
    for host, c in certs.items():
        if not isinstance(c, dict):
            continue
        days = c.get("days_left")
        try:
            days = int(days) if days is not None else None
        except (TypeError, ValueError):
            days = None
        issues = []
        if c.get("expired"):
            issues.append("expired")
        elif c.get("expiring_soon"):
            issues.append("expiring soon")
        if c.get("self_signed"):
            issues.append("self-signed")
        if c.get("hostname_ok") is False:
            issues.append("hostname mismatch")
        if c.get("chain_trusted") is False and not c.get("self_signed"):
            issues.append("untrusted chain")
        rows.append({
            "host": str(host),
            "port": c.get("port"),
            "subject_cn": c.get("subject_cn") or "",
            "issuer_cn": c.get("issuer_cn") or "",
            "issuer_org": c.get("issuer_org") or "",
            "not_after": c.get("not_after") or "",
            "not_before": c.get("not_before") or "",
            "days_left": days,
            "expired": bool(c.get("expired")),
            "expiring_soon": bool(c.get("expiring_soon")),
            "self_signed": bool(c.get("self_signed")),
            "hostname_ok": c.get("hostname_ok"),
            "chain_trusted": c.get("chain_trusted"),
            "san_count": c.get("san_count") or 0,
            "sans": c.get("sans") or [],
            "key_bits": c.get("key_bits"),
            "issues": issues,
            "status": "ISSUE" if issues else "OK",
        })
    # expiring/expired first, then fewest days left, then hosts with issues
    rows.sort(key=lambda r: (
        0 if r["expired"] else 1,
        r["days_left"] if r["days_left"] is not None else 10 ** 6,
        0 if r["issues"] else 1,
        r["host"],
    ))
    return rows


def certificate_summary(rows):
    """Aggregate counts for the certificate inventory header."""
    rows = rows or []
    return {
        "total": len(rows),
        "ok": sum(1 for r in rows if not r["issues"]),
        "expired": sum(1 for r in rows if r["expired"]),
        "expiring_soon": sum(1 for r in rows if r["expiring_soon"]),
        "self_signed": sum(1 for r in rows if r["self_signed"]),
        "hostname_mismatch": sum(1 for r in rows if "hostname mismatch" in r["issues"]),
        "untrusted_chain": sum(1 for r in rows if "untrusted chain" in r["issues"]),
        "issuers": sorted({r["issuer_org"] or r["issuer_cn"] for r in rows
                           if (r["issuer_org"] or r["issuer_cn"])}),
    }


def _kind_for(product):
    """Coarse category for a detected product ('cms', 'js-framework', ...)."""
    try:
        import tech_detect
        return tech_detect.kind_of(product)
    except Exception:
        return "other"


def software_from_meta(meta, findings=None):
    """Software inventory: observed product/version pairs plus matched CVEs.

    Sources are the passive fingerprints captured per host (meta.fingerprints,
    each carrying a `versions` list from banner/header/title parsing). CVEs are
    resolved two ways and unioned per host:

      - by re-running the offline CVE map against each observed pair, so the
        inventory is correct even when finding synthesis was skipped or the
        finding was deduped away by a previous scan;
      - from existing `scan-cve` findings, which carry operator-visible ids.

    One row per (host, product, version) so a host running several disclosed
    products lists them all.
    """
    meta = meta or {}
    fps = meta.get("fingerprints") or {}
    findings = findings or []

    # target -> cves seen in that host's CVE findings
    cves_by_host = defaultdict(set)
    finding_by_host = {}
    for f in findings:
        if str(f.get("source", "")) != "scan-cve":
            continue
        tgt = str(f.get("target", "")).strip().lower()
        for c in _norm_cves(f.get("related_cves")):
            cves_by_host[tgt].add(c)
        finding_by_host.setdefault(tgt, f.get("id"))

    try:
        import cve_match
    except Exception:          # pragma: no cover - import guard for app paths
        cve_match = None
    # ids the current map rules on: matched ones it rejects for a version, and
    # ones withdrawn outright (e.g. client-side flaws a server banner cannot show)
    mapped_ids = ({c["cve"] for entry in cve_match.load_map().values() for c in entry["cves"]}
                  | cve_match.withdrawn_ids()) if cve_match else set()
    live_pkgs, _ = _live_intel(meta)

    rows = []
    for host, s in (fps.items() if isinstance(fps, dict) else []):
        if not isinstance(s, dict):
            continue
        h = str(host)
        versions = s.get("versions") or []
        # framework detections carry their own kind/confidence/source; an
        # identity-only detection (no version) is still inventory-worthy but
        # is NEVER CVE-matched, so it is emitted with an empty version
        details = s.get("tech_detail") or []
        detail_by_product = {}
        if isinstance(details, list):
            for d in details:
                if isinstance(d, dict) and d.get("product"):
                    detail_by_product[str(d["product"]).lower()] = d
        if not isinstance(versions, list) or not versions:
            # no banner versions; a framework may still be identifiable below
            versions = []
        host_cves = set(cves_by_host.get(h.strip().lower(), set()))
        # CVE attribution must be PER PRODUCT, not per host: matching the
        # host's whole version list against the map and then showing that set
        # on every row would put the WordPress CVE on the nginx row. Each
        # product is matched on its own pair.
        cves_by_product = {}
        if cve_match is not None:
            for v in (versions if isinstance(versions, list) else []):
                if not isinstance(v, dict):
                    continue
                prod = str(v.get("product") or "").strip().lower()
                if not prod:
                    continue
                try:
                    hits = cve_match.match_cves([v])
                except Exception:
                    hits = []
                ids = {str(m["cve"]) for m in hits if m.get("cve")}
                ids.update(_live_package_ids(live_pkgs, prod, v.get("version")))
                cves_by_product.setdefault(prod, set()).update(ids)
        # findings-declared CVEs remain a host-level fallback for products the
        # live map does not cover (e.g. an AI- or NVD-derived match)
        seen_rows = set()

        def _emit(product, version, source, confidence, versioned):
            key = (product.lower(), version)
            if key in seen_rows:
                return
            seen_rows.add(key)
            det = detail_by_product.get(product.lower()) or {}
            prod_cves = set(cves_by_product.get(product.lower(), set()))
            if not prod_cves and not version:
                prod_cves = set()          # identity-only: nothing to match
            elif not prod_cves:
                # no product-level match; fall back to host-level only when
                # this is the host's sole versioned product (unambiguous)
                versioned_products = [x for x in (versions if isinstance(versions, list) else [])
                                      if isinstance(x, dict) and x.get("version")]
                if len(versioned_products) == 1:
                    # A historical finding must not resurrect a match that
                    # the current advisory map rejects for this version.
                    prod_cves = host_cves - mapped_ids
            rows.append({
                "host": h,
                "product": product,
                "version": version,
                "kind": det.get("kind") or _kind_for(product),
                "confidence": det.get("confidence") or confidence,
                "detected_by": det.get("source") or source,
                "versioned": bool(version),
                "url": s.get("url") or "",
                "server": s.get("server") or "",
                "x_powered_by": s.get("x-powered-by") or "",
                "related_cves": sorted(prod_cves),
                "cve_count": len(prod_cves),
                "finding_id": finding_by_host.get(h.strip().lower()),
            })

        for v in (versions if isinstance(versions, list) else []):
            if not isinstance(v, dict):
                continue
            product = str(v.get("product") or "").strip()
            version = str(v.get("version") or "").strip()
            if not product and not version:
                continue
            det = detail_by_product.get(product.lower()) or {}
            _emit(product, version, "banner", det.get("confidence") or "medium",
                  bool(version))
        # identity-only framework detections (no version to match against)
        for d in (details if isinstance(details, list) else []):
            if not isinstance(d, dict) or d.get("version"):
                continue
            product = str(d.get("product") or "").strip()
            if product:
                _emit(product, "", d.get("source") or "html",
                      d.get("confidence") or "low", False)
    rows.sort(key=lambda r: (-r["cve_count"], r["host"], r["product"]))
    return rows


def software_summary(rows):
    """Aggregate counts for the software inventory header."""
    rows = rows or []
    prod = defaultdict(int)
    kind = defaultdict(int)
    for r in rows:
        if r["product"]:
            prod[r["product"].lower()] += 1
        if r.get("kind"):
            kind[r["kind"]] += 1
    return {
        "total": len(rows),
        "hosts": len({r["host"] for r in rows}),
        "vulnerable": sum(1 for r in rows if r["cve_count"]),
        "versioned": sum(1 for r in rows if r.get("versioned")),
        "products": sorted(prod.items(), key=lambda x: -x[1])[:20],
        "kinds": dict(sorted(kind.items(), key=lambda x: -x[1])),
    }


def build_graph_from_data(fs, baseline, domains=None):
    """Correlation graph from in-memory findings/baseline/domains."""
    fs = fs or []
    baseline = baseline or []
    domains = domains or []
    nodes = {}
    edges = []

    def add_node(id_, label, type_, **kw):
        if id_ not in nodes:
            n = {"id": id_, "label": label, "type": type_,
                 "color": NODE_COLORS.get(type_, "#888"), **kw}
            nodes[id_] = n
        return nodes[id_]

    def add_edge(a, b, label, **kw):
        edges.append({"from": a, "to": b, "label": label, **kw})

    for f in fs:
        tgt = str(f.get("target", "")).strip() or "?"
        sev = str(f.get("severity", "INFO")).upper()
        cat = str(f.get("category", "")).strip()
        add_node("host:" + tgt, _html.escape(tgt), "host", sev=sev,
                 title=f"<b>{_html.escape(tgt)}</b><br>sev: {_html.escape(sev)} — {_html.escape(cat)}")

        ip = str(f.get("ip", "")).strip()
        if ip and ip != "None":
            add_node("ip:" + ip, _html.escape(ip), "ip", sev=sev,
                     title=_html.escape(f"IP: {ip}"))
            add_edge("ip:" + ip, "host:" + tgt, "resolves\u2192")

        root = _root_domain(tgt, domains)
        if root not in ("raw-ip", "other"):
            add_node("brand:" + root, _html.escape(root), "brand")
            add_edge("host:" + tgt, "brand:" + root, "part-of")

        if cat:
            add_node("class:" + cat, _html.escape(cat[:40]), "class",
                     title=_html.escape(f"Class: {cat[:80]}"))
            add_edge("host:" + tgt, "class:" + cat, "is")

        for c in _norm_cves(f.get("related_cves")):
            add_node("cve:" + c, _html.escape(c), "cve", sev=sev,
                     title=_html.escape(f"CVE: {c}"))
            add_edge("host:" + tgt, "cve:" + c, "has")

    for h in baseline:
        if f"host:{h}" not in nodes:
            ip = None
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
                ip = h
            if ip:
                add_node("ip:" + ip, _html.escape(ip), "ip")
                add_node("host:" + h, _html.escape(h), "host", sev="INFO")
                add_edge("ip:" + ip, "host:" + h, "resolves\u2192")
            else:
                add_node("host:" + h, _html.escape(h), "host", sev="INFO")
                root = _root_domain(h, domains)
                if root not in ("raw-ip", "other"):
                    add_node("brand:" + root, _html.escape(root), "brand")
                    add_edge("host:" + h, "brand:" + root, "part-of")

    ip_clusters = defaultdict(list)
    for e in edges:
        if e.get("label") == "resolves\u2192" and e["from"].startswith("ip:"):
            ip_clusters[e["from"]].append(e["to"])
    cve_hosts = defaultdict(list)
    for e in edges:
        if e.get("label") == "has" and e["to"].startswith("cve:"):
            cve_hosts[e["to"]].append(e["from"])

    for ip, hosts in ip_clusters.items():
        if len(hosts) >= 2:
            add_node("ip:" + ip, _html.escape(ip.split(":", 1)[1]), "ip",
                     cluster=True, title=f"<b>Shared box</b><br>{len(hosts)} hosts")
            for h in hosts[1:]:
                add_edge(hosts[0], h, "co-resident", dashes=True, color="#6a6a6a")

    for cve, hosts in cve_hosts.items():
        if len(hosts) >= 2:
            pass

    return {"nodes": list(nodes.values()), "edges": edges,
            "meta": {"findings": len(fs), "baseline": len(baseline)}}


def find_finding(org, id_):
    """Return the full finding dict for (org, id_) or None."""
    fs, _ = load_data(org)
    for f in fs:
        if str(f.get("id")) == str(id_):
            return f
    return None


def build_graph(org=DEFAULT_ORG):
    """Return {nodes:[...], edges:[...]} for the correlation graph."""
    fs, baseline = load_data(org)
    domains = (REGISTRY.get(org) or {}).get("domains") or []
    return build_graph_from_data(fs, baseline, domains)


def fleet_spread(org=DEFAULT_ORG):
    """Same CVE across multiple hosts -> shared remediation priority."""
    fs, _ = load_data(org)
    return fleet_spread_from_data(fs)


def ip_sharing(org=DEFAULT_ORG):
    """Co-residency: same IP serving multiple hosts."""
    fs, _ = load_data(org)
    return ip_sharing_from_data(fs)


def summary(org=DEFAULT_ORG):
    fs, baseline = load_data(org)
    return summary_from_data(fs, baseline)


def certificates(org=DEFAULT_ORG):
    """Certificate inventory for an org (all inspected hosts, worst-first)."""
    fs, _ = load_data(org)
    meta = load_meta(org)
    rows = certificates_from_meta(meta)
    # attach the finding id for each host so the UI can drill through
    by_host = {}
    for f in (fs or []):
        if str(f.get("source", "")) == "scan-tls":
            by_host.setdefault(str(f.get("target", "")).strip().lower(), f.get("id"))
    for r in rows:
        r["finding_id"] = by_host.get(r["host"].strip().lower())
    return {"summary": certificate_summary(rows), "certificates": rows,
            "scanned": meta.get("date") or ""}


def software(org=DEFAULT_ORG):
    """Software/version inventory for an org, with matched CVE counts."""
    fs, _ = load_data(org)
    meta = load_meta(org)
    rows = software_from_meta(meta, fs)
    return {"summary": software_summary(rows), "software": rows,
            "scanned": meta.get("date") or ""}


def dns_posture(org=DEFAULT_ORG):
    """DNS / email-authentication posture per registered domain."""
    try:
        import dns_posture as dp
        summarize = dp.summarize
    except Exception:                      # pragma: no cover - import guard
        def summarize(rows):
            return {"domains": len(rows or [])}
    meta = load_meta(org)
    results = meta.get("dns_posture") or []
    if not isinstance(results, list):
        results = []
    return {"summary": summarize(results), "domains": results,
            "scanned": meta.get("date") or ""}


def dependencies_from_meta(meta, domains=()):
    """Outside-in package and dependency inventory from one scan snapshot.

    packages   one row per (package, version) across hosts: server software
               and frameworks from banners/markup, front-end libraries and
               WordPress plugins/themes from the scripts each page loads —
               with every matched CVE, its fix version, and lifecycle status
    origins    third-party hosts that pages load scripts/styles from
    providers  service providers implied by DNS records and script origins

    Read-only and offline: CVEs come from the vendored map, lifecycle and
    provider rules from dependencies.py. Evidence strings are PII-masked;
    product and version fields are not (a 4-part version looks like an IP).
    """
    import cve_match
    import dependencies as deps
    import tech_detect
    meta = meta or {}
    fps = meta.get("fingerprints") or {}
    if not isinstance(fps, dict):
        fps = {}
    owned = [str(d).strip().lower().rstrip(".") for d in domains or () if str(d).strip()]

    def first_party(host):
        return any(host == d or host.endswith("." + d) for d in owned)

    def where(text):
        return _mask_value("evidence", str(text or ""))[:200]

    packages, origins = {}, {}
    pages = 0

    def add(name, version, kind, host, evidence, source):
        key = (str(name).lower(), str(version or ""))
        row = packages.setdefault(key, {
            "package": str(name), "version": str(version or ""), "kind": kind,
            "hosts": [], "evidence": []})
        if host not in row["hosts"]:
            row["hosts"].append(host)
        if len(row["evidence"]) < 12 and not any(
                e["host"] == host and e["where"] == evidence for e in row["evidence"]):
            row["evidence"].append({"host": host, "where": evidence, "source": source})

    for host, s in sorted(fps.items()):
        if not isinstance(s, dict):
            continue
        details = {str(d.get("product", "")).lower(): d for d in (s.get("tech_detail") or [])
                   if isinstance(d, dict)}
        assets = s.get("assets") if isinstance(s.get("assets"), list) else None
        asset_libs = {(str(a.get("library") or "").lower(), str(a.get("version") or ""))
                      for a in assets or () if isinstance(a, dict)}
        for v in s.get("versions") or ():
            if not isinstance(v, dict) or not v.get("product"):
                continue
            product, version = str(v["product"]), str(v.get("version") or "")
            if (product.lower(), version) in asset_libs:
                continue           # reported below with the asset URL as evidence
            det = details.get(product.lower()) or {}
            evidence = det.get("evidence") or next(
                (("%s: %s" % (h, s[h])) for h in ("server", "x-powered-by", "x-generator", "generator")
                 if product.lower() in str(s.get(h) or "").lower()), "response headers / markup")
            add(product, version, tech_detect.kind_of(product), host, where(evidence),
                det.get("source") or "banner")
        for product, det in details.items():
            if not det.get("version") and product:
                add(det.get("product") or product, "", tech_detect.kind_of(product), host,
                    where(det.get("evidence") or ""), det.get("source") or "markup")
        if assets is None:
            continue
        pages += 1
        for a in assets:
            if not isinstance(a, dict):
                continue
            lib = a.get("library")
            if lib:
                kind = ("wordpress-plugin" if lib.startswith("wp-plugin/") else
                        "wordpress-theme" if lib.startswith("wp-theme/") else
                        tech_detect.kind_of(lib) if tech_detect.kind_of(lib) != "other" else
                        "js-library" if a.get("kind") == "script" else "css-framework")
                add(lib, a.get("version"), kind, host, where(a.get("url")), a.get("source") or "asset")
            ahost = str(a.get("host") or "")
            if a.get("third_party") and not first_party(ahost):
                o = origins.setdefault(ahost, {
                    "host": ahost, "provider": None, "category": None,
                    "pages": [], "assets": 0, "scripts": 0, "with_sri": 0,
                    "compromised": deps.compromised(ahost), "insecure": 0})
                known = deps.script_provider(ahost)
                if known:
                    o["provider"], o["category"] = known
                if host not in o["pages"]:
                    o["pages"].append(host)
                o["assets"] += 1
                o["scripts"] += a.get("kind") == "script"
                o["with_sri"] += bool(a.get("sri"))
                o["insecure"] += bool(a.get("insecure"))

    import live_cve
    live_pkgs, live_cves = _live_intel(meta)
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows = []
    for row in packages.values():
        cves = {}
        if row["version"]:
            try:
                for c in cve_match.match_cves([{"product": row["package"], "version": row["version"]}]):
                    cves[c["cve"]] = {k: c.get(k) for k in ("cve", "severity", "cvss", "summary",
                                                             "fix_version", "confidence")}
                    cves[c["cve"]]["source"] = "offline map"
            except Exception:
                pass
        for cid in _live_package_ids(live_pkgs, row["package"], row["version"]):
            cves.setdefault(cid, {"cve": cid, "source": "cve.now", "confidence": "medium"})
        for cid, c in cves.items():
            rec = live_cves.get(cid)
            if not rec:
                continue
            c.update(
                severity=live_cve.severity_of(rec) or c.get("severity") or "MEDIUM",
                cvss=rec.get("cvss") if rec.get("cvss") is not None else c.get("cvss"),
                vector=rec.get("vector") or None,
                summary=rec.get("title") or rec.get("summary") or c.get("summary") or "",
                fix_version=rec.get("fixed") or c.get("fix_version"),
                kev=rec.get("kev"), exploit_db=bool(rec.get("exploit_db")),
                published=rec.get("published"),
                source="cve.now" if c.get("source") == "cve.now" else "offline map + cve.now")
        cves = sorted(cves.values(), key=lambda c: (
            not c.get("kev"), sev_rank.get(str(c.get("severity") or "").upper(), 9), c["cve"]))
        fixes = [c["fix_version"] for c in cves if c.get("fix_version")]
        eol = deps.end_of_life(row["package"], row["version"])
        worst = min((str(c.get("severity") or "MEDIUM").upper() for c in cves),
                    key=lambda s: sev_rank.get(s, 9), default=None)
        row.update(
            cves=cves, cve_count=len(cves), worst=worst,
            known_exploited=sum(1 for c in cves if c.get("kev")),
            upgrade_to=max(fixes, key=cve_match._vkey) if fixes else None,
            end_of_life=eol,
            status=("vulnerable" if cves else "end-of-life" if eol else
                    "unversioned" if not row["version"] else "no known CVE"))
        rows.append(row)
    status_rank = {"vulnerable": 0, "end-of-life": 1, "no known CVE": 2, "unversioned": 3}
    rows.sort(key=lambda r: (status_rank[r["status"]], not r["known_exploited"],
                             sev_rank.get(r["worst"], 9), -len(r["hosts"]),
                             r["package"], r["version"]))

    providers = {}
    dns = meta.get("dns_posture") if isinstance(meta.get("dns_posture"), list) else []
    found = [p for v in dns if isinstance(v, dict) and isinstance(v.get("records"), dict)
             for p in deps.providers_from_records(v.get("domain"), v["records"])]
    found += [{"provider": o["provider"], "category": o["category"], "source": "script",
               "domain": ", ".join(o["pages"][:3]), "evidence": o["host"]}
              for o in origins.values() if o["provider"]]
    for p in found:
        row = providers.setdefault(p["provider"], {
            "provider": p["provider"], "category": p["category"],
            "sources": [], "domains": [], "evidence": []})
        if p["source"] not in row["sources"]:
            row["sources"].append(p["source"])
        if p["domain"] and p["domain"] not in row["domains"]:
            row["domains"].append(p["domain"])
        if len(row["evidence"]) < 6:
            row["evidence"].append(where("%s: %s" % (p["source"], p["evidence"])))
    origin_rows = sorted(origins.values(), key=lambda o: (
        not o["compromised"], -len(o["pages"]), o["host"]))
    return {
        "summary": {
            "pages": pages,
            "packages": len(rows),
            "vulnerable": sum(1 for r in rows if r["status"] == "vulnerable"),
            "critical": sum(1 for r in rows if r["worst"] == "CRITICAL"),
            "known_exploited": sum(1 for r in rows if r["known_exploited"]),
            "end_of_life": sum(1 for r in rows if r["end_of_life"]),
            "cves": sum(r["cve_count"] for r in rows),
            "third_party_origins": len(origin_rows),
            "compromised": sum(1 for o in origin_rows if o["compromised"]),
            "providers": len(providers),
        },
        "packages": rows,
        "intel": _intel_status(meta),
        "origins": origin_rows,
        "providers": sorted(providers.values(), key=lambda p: (p["category"] or "", p["provider"])),
    }


def dependency_snapshot(meta, domains=()):
    """Compact per-scan record of what each page loads, for drift detection.

    `pages` lists the hosts whose markup was examined, so a page that simply
    failed to load next time is never mistaken for scripts being removed.
    """
    inv = dependencies_from_meta(meta, domains)
    fps = (meta or {}).get("fingerprints") or {}
    pages = sorted(h for h, s in (fps.items() if isinstance(fps, dict) else [])
                   if isinstance(s, dict) and isinstance(s.get("assets"), list))
    return {
        "pages": pages[:500],
        "origins": sorted({"%s>%s" % (page, o["host"])
                           for o in inv["origins"] for page in o["pages"]})[:1000],
        "packages": sorted({"%s>%s@%s" % (host, p["package"], p["version"])
                            for p in inv["packages"] if p["version"]
                            for host in p["hosts"]})[:1000],
    }


def dependency_changes(current, events):
    """What pages load now that they did not at the preceding scan.

    Only pages examined in BOTH scans are compared: a first look at a page
    is a baseline, not drift, and a page that failed to load is not a
    removal. A new third-party origin on a known page is the externally
    visible signature of script injection (Magecart-style skimmers), so it
    is reported even when nothing else changed.
    """
    scans = [e for e in events or () if isinstance(e, dict) and e.get("kind") == "scan"
             and isinstance(e.get("dependencies"), dict)]
    previous = scans[-1] if scans else None
    if previous and previous["dependencies"] == current:
        previous = scans[-2] if len(scans) > 1 else None
    if not previous:
        return {"baseline_at": None, "new_origins": [], "removed_origins": [],
                "new_packages": [], "removed_packages": [], "version_changes": []}
    old = previous["dependencies"]
    both = set(current.get("pages") or ()) & set(old.get("pages") or ())

    def on_known_pages(items):
        return {i for i in items if i.split(">", 1)[0] in both}

    def split(item):
        page, rest = item.split(">", 1)
        return page, rest

    now_o, old_o = on_known_pages(current.get("origins") or ()), on_known_pages(old.get("origins") or ())
    now_p, old_p = on_known_pages(current.get("packages") or ()), on_known_pages(old.get("packages") or ())
    old_names = {}
    for item in old_p:
        page, pkg = split(item)
        old_names.setdefault((page, pkg.rsplit("@", 1)[0]), set()).add(pkg.rsplit("@", 1)[1])
    changes, added = [], []
    for item in sorted(now_p - old_p):
        page, pkg = split(item)
        name, version = pkg.rsplit("@", 1)
        before = old_names.get((page, name))
        if before:
            changes.append({"page": page, "package": name, "from": sorted(before), "to": version})
        else:
            added.append({"page": page, "package": name, "version": version})
    changed = {(c["page"], c["package"]) for c in changes}
    removed = []
    for item in sorted(old_p - now_p):
        page, pkg = split(item)
        name, version = pkg.rsplit("@", 1)
        if (page, name) not in changed:
            removed.append({"page": page, "package": name, "version": version})
    import dependencies as deps
    return {
        "baseline_at": previous.get("ts"),
        "new_origins": [{"page": p, "origin": o, "compromised": deps.compromised(o),
                         "provider": (deps.script_provider(o) or (None,))[0]}
                        for p, o in (split(i) for i in sorted(now_o - old_o))],
        "removed_origins": [{"page": p, "origin": o} for p, o in (split(i) for i in sorted(old_o - now_o))],
        "new_packages": added, "removed_packages": removed, "version_changes": changes,
    }


def _intel_status(meta):
    """Where the CVE data on this page came from, for the freshness note."""
    import live_cve
    live = (meta or {}).get("live_cves")
    status = {"offline_map": True, "live_enabled": live_cve.enabled(), "live": None}
    if isinstance(live, dict):
        status["live"] = {k: live.get(k) for k in ("source", "fetched_at", "complete", "errors")}
        status["live"]["packages"] = len(live.get("packages") or {})
        status["live"]["advisories"] = len(live.get("cves") or {})
    return status


def refresh_live_cves(org=DEFAULT_ORG):
    """Re-capture live advisories for the current snapshot (explicit action).

    Network I/O happens before the org lock; the write is a single locked
    read-modify-write of meta.live_cves, so a concurrent scan's evidence is
    never overwritten with intel fetched for an older snapshot.
    """
    import live_cve
    fs, _, _, meta = copy.deepcopy(_cached_org_data(org))
    date = (meta or {}).get("date")
    live = live_cve.collect((meta or {}).get("fingerprints") or {})
    path = org_findings_path(org)
    with _org_lock(org):
        with open(path) as f:
            d = json.load(f)
        current = d.setdefault("meta", {})
        if current.get("date") != date:
            return {"updated": False, "reason": "a newer scan replaced the snapshot; rescan or retry"}
        current["live_cves"] = live
        _atomic_write_json(path, d)
    invalidate_org_cache(org)
    return {"updated": True, "live": {k: live[k] for k in ("fetched_at", "complete", "errors")},
            "packages": len(live["packages"]), "advisories": len(live["cves"])}


def dependencies(org=DEFAULT_ORG):
    fs, _, _, meta = copy.deepcopy(_cached_org_data(org))
    domains = (REGISTRY.get(org) or {}).get("domains") or []
    result = dependencies_from_meta(meta, domains)
    result["scanned"] = meta.get("date") or ""
    result["changes"] = dependency_changes(dependency_snapshot(meta, domains), load_history(org))
    return result


def _cvss_method(vector):
    v = str(vector or "")
    if v.startswith("CVSS:4.0"):
        return "CVSSv4"
    if v.startswith("CVSS:3.1"):
        return "CVSSv31"
    return "CVSSv3"


def _purl(package, version):
    from urllib.parse import quote
    import dependencies as deps
    name = deps.NPM_NAMES.get(package)
    if name:
        return "pkg:npm/%s@%s" % (quote(name, safe="/"), quote(version))
    if package.startswith(("wp-plugin/", "wp-theme/")):
        return None
    return "pkg:generic/%s@%s" % (quote(package, safe=""), quote(version))


def dependencies_cyclonedx(org=DEFAULT_ORG):
    """CycloneDX 1.5 BOM of the externally observed components and their CVEs.

    Declared `incomplete`: an outside-in view sees only what pages and
    banners disclose, never the full dependency tree of an application.
    """
    import uuid
    inv = dependencies(org)
    org_meta = REGISTRY.get(org) or {}
    components, vulns = [], {}
    for i, p in enumerate(p for p in inv["packages"] if p["version"]):
        ref = "component-%d" % (i + 1)
        comp = {"type": "framework" if p["kind"] in ("js-framework", "server-framework", "cms")
                else "library", "bom-ref": ref, "name": p["package"], "version": p["version"],
                "properties": [{"name": "parallax:observed-on", "value": h} for h in p["hosts"][:20]]
                + [{"name": "parallax:evidence", "value": e["where"]} for e in p["evidence"][:5]]}
        purl = _purl(p["package"], p["version"])
        if purl:
            comp["purl"] = purl
        if p.get("end_of_life"):
            comp["properties"].append({"name": "parallax:end-of-life", "value": p["end_of_life"]})
        components.append(comp)
        for c in p["cves"]:
            v = vulns.setdefault(c["cve"], {
                "bom-ref": "vuln-" + c["cve"], "id": c["cve"],
                "source": {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + c["cve"]},
                "ratings": [{"severity": str(c.get("severity") or "unknown").lower(),
                             **({"score": c["cvss"], "method": _cvss_method(c.get("vector"))}
                                if c.get("cvss") is not None else {})}],
                **({"properties": [{"name": "parallax:cisa-kev-added",
                                    "value": str((c.get("kev") or {}).get("added") or "")}]}
                   if c.get("kev") else {}),
                "description": c.get("summary") or "",
                "affects": []})
            v["affects"].append({"ref": ref})
            if c.get("fix_version"):
                v["recommendation"] = "Upgrade to %s or later." % c["fix_version"]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(), "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": {"components": [{"type": "application", "name": "Parallax"}]},
            "component": {"type": "application", "bom-ref": "org", "name": org_meta.get("name") or org},
            "properties": [{"name": "parallax:collection",
                            "value": "external passive observation, scan of %s" % (inv.get("scanned") or "unknown date")}],
        },
        "components": components,
        "compositions": [{"aggregate": "incomplete", "assemblies": ["org"]}],
        "vulnerabilities": list(vulns.values()),
    }


def _live_intel(meta):
    """(packages {key: [ids]}, cves {id: record}) captured from cve.now, or empties."""
    live = (meta or {}).get("live_cves")
    if not isinstance(live, dict):
        return {}, {}
    pkgs = live.get("packages") if isinstance(live.get("packages"), dict) else {}
    cves = live.get("cves") if isinstance(live.get("cves"), dict) else {}
    return pkgs, {k: v for k, v in cves.items() if isinstance(v, dict)}


def _live_package_ids(live_pkgs, product, version):
    """Live advisory ids for one observed (product, version), via its npm name."""
    import dependencies as deps
    import live_cve
    name = deps.NPM_NAMES.get(str(product or "").lower())
    if not name or not version:
        return []
    ids = live_pkgs.get(live_cve.package_key("npm", name, version))
    return [str(i) for i in ids] if isinstance(ids, list) else []


def _known_exploited(meta):
    """CVE ids the captured live intel lists in CISA KEV."""
    _, cves = _live_intel(meta)
    return {cid for cid, rec in cves.items() if rec.get("kev")}


def _cve_severity_map(meta=None):
    """{CVE id -> severity}: the vendored map, overridden by live intel.

    Live CVSS (from the CNA or NVD via cve.now) is the fresher, cited source,
    so it wins where present; the curated map fills the gaps.
    """
    out = {}
    try:
        import cve_match
        for entry in (cve_match.load_map() or {}).values():
            for cve in entry.get("cves", []):
                cid = str(cve.get("cve") or "").upper()
                sev = str(cve.get("severity") or "").upper()
                ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                if cid and sev in ranks:
                    # keep the worst severity if an id appears under two products
                    if ranks[sev] < ranks.get(out.get(cid), 9):
                        out[cid] = sev
    except Exception:
        pass
    import live_cve
    for cid, rec in _live_intel(meta)[1].items():
        sev = live_cve.severity_of(rec)
        if sev:
            out[cid] = sev
    return out


def scorecard_from_snapshot(domains, meta, fs, exclude=(), explain=True):
    """Composite per-domain scorecard over the asset inventories.

    Deterministic and fully itemized: the response carries every deduction,
    the coverage actually examined, and any cap that was applied, so a reader
    can reproduce the number instead of trusting it. `exclude` treats issue
    types as fixed (the score planner); `explain` adds exact per-item gains
    and the org-wide issue list.
    """
    import scorecard as sc
    software_rows = software_from_meta(meta, fs)
    cert_rows = certificates_from_meta(meta)
    dns_results = meta.get("dns_posture") or []
    if not isinstance(dns_results, list):
        dns_results = []
    severity_map = _cve_severity_map(meta)
    exploited = _known_exploited(meta)

    def rebuild(more=(), explain=False):
        return sc.build(domains, meta, software_rows=software_rows,
                        cert_rows=cert_rows, dns_results=dns_results,
                        severity_map=severity_map,
                        exclude=set(exclude) | set(more), explain=explain,
                        exploited=exploited)

    cards = rebuild(explain=explain)
    import posture
    result = {"summary": sc.summarize(cards), "domains": cards,
              "scanned": meta.get("date") or "",
              "actions": posture.action_plan(cards),
              "snapshot": posture.snapshot(cards, meta)}
    result["issues"] = sc.org_issues(cards, rebuild if explain else None)
    return result


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def hosts_from_snapshot(domains, meta, fs, only=None):
    """Per-host (subdomain) ratings, weakest first, from one scan snapshot.

    Each host is scored by the same model as its domain, from its own
    evidence plus its domain's email & DNS verdict. Issue lists leave out the
    inherited DNS deductions so they show what is specific to the host; a
    takeover is kept, because it belongs to the host it was found on. An
    unrated host has score None, never a 0 that reads like a result.
    `only` returns just that host, with exact host-score gains per issue.
    """
    import scorecard as sc
    meta = meta or {}
    software_rows = software_from_meta(meta, fs)
    cert_rows = certificates_from_meta(meta)
    dns_results = meta.get("dns_posture") if isinstance(meta.get("dns_posture"), list) else []
    cards = sc.build_hosts(domains, meta, software_rows=software_rows, cert_rows=cert_rows,
                           dns_results=dns_results, severity_map=_cve_severity_map(meta),
                           exploited=_known_exploited(meta), only=only, explain=bool(only))
    open_by_host = defaultdict(int)
    for f in fs or []:
        if str(f.get("status") or "OPEN").upper() in ("OPEN", "IN_PROGRESS"):
            open_by_host[str(f.get("target") or "").strip().lower()] += 1
    services = meta.get("services") if isinstance(meta.get("services"), dict) else {}
    rows = []
    for c in cards:
        issues = []
        for p in c["pillars"]:
            for d in p["deductions"]:
                if p["pillar"] == "email_dns" and d["type"] != "dns-takeover":
                    continue
                info = sc.ISSUE_TYPES.get(d["type"]) or {}
                issue = {"type": d["type"], "title": info.get("title") or d["type"],
                         "label": d["label"], "severity": info.get("severity", "low"),
                         "factor": p["pillar"], "points": d["points"], "detail": d.get("detail", "")}
                if "gain" in d:
                    issue["gain"] = d["gain"]
                issues.append(issue)
        issues.sort(key=lambda i: (_SEV_RANK.get(i["severity"], 9), -i["points"]))
        counts = defaultdict(int)
        for i in issues:
            counts[i["severity"]] += 1
        rows.append({
            "host": c["host"], "domain": c["parent"], "kind": c.get("kind", "domain"),
            "score": None if c["unknown"] else c["score"], "grade": c["grade"],
            "coverage": c["coverage"], "confidence": c["confidence"], "unknown": c["unknown"],
            "critical_exposure": bool(c.get("critical_exposure")),
            "critical_cap": c.get("critical_cap"), "coverage_cap": c.get("coverage_cap"),
            "factors": {p["pillar"]: p.get("score") for p in c["pillars"]},
            "notes": {p["pillar"]: p.get("note") for p in c["pillars"]},
            "issues": issues if only else issues[:12],
            "issue_counts": dict(counts),
            "open_ports": sorted((services.get(c["host"]) or {}).get("open") or {}, key=lambda p: int(p) if str(p).isdigit() else 0),
            "open_findings": open_by_host.get(c["host"], 0),
        })
    rated = [r for r in rows if not r["unknown"]]
    by_grade = defaultdict(int)
    for r in rows:
        by_grade[r["grade"]] += 1
    return {"hosts": rows, "summary": {"hosts": len(rows), "rated": len(rated),
                                       "by_grade": dict(sorted(by_grade.items())),
                                       "with_critical": sum(1 for r in rows if r["critical_exposure"])}}


def hosts(org=DEFAULT_ORG, only=None):
    fs, _, _, meta = copy.deepcopy(_cached_org_data(org))
    result = hosts_from_snapshot((REGISTRY.get(org) or {}).get("domains") or [], meta, fs, only=only)
    result["scanned"] = meta.get("date") or ""
    return result


def scorecard(org=DEFAULT_ORG, explain=True):
    # One cache read keeps findings and evidence from the same scan.
    fs, _, _, meta = copy.deepcopy(_cached_org_data(org))
    result = scorecard_from_snapshot((REGISTRY.get(org) or {}).get("domains") or [],
                                     meta, fs, explain=explain)
    import posture
    result["progress"] = posture.progress(result.pop("snapshot"), load_history(org))
    return result


def scorecard_plan(org=DEFAULT_ORG, fix=()):
    """Score planner: the org rating with the given issue types treated as fixed.

    Both sides come from one snapshot through the same model, so the
    projection differs from the live rating only by the selected fixes.
    """
    fs, _, _, meta = copy.deepcopy(_cached_org_data(org))
    domains = (REGISTRY.get(org) or {}).get("domains") or []
    before = scorecard_from_snapshot(domains, meta, fs, explain=False)
    after = scorecard_from_snapshot(domains, meta, fs, exclude=fix, explain=False)
    return {
        "fix": sorted(set(fix)),
        "before": before["summary"], "after": after["summary"],
        "domains": [{"domain": b["domain"], "unknown": b["unknown"],
                     "before": b["score"], "after": a["score"],
                     "grade_before": b["grade"], "grade_after": a["grade"]}
                    for b, a in zip(before["domains"], after["domains"])],
    }


def portfolio():
    """Every registered org's rating side by side — read-only, like
    scorecard(): no history is written and nothing is rescanned."""
    rows = []
    for slug in sorted(REGISTRY):
        org = REGISTRY.get(slug) or {}
        row = {"slug": slug, "name": org.get("name") or slug,
               "domains": len(org.get("domains") or [])}
        try:
            data = scorecard(slug, explain=False)
        except Exception as e:
            row["error"] = type(e).__name__
            rows.append(row)
            continue
        severities = {}
        for issue in data.get("issues") or []:
            severities[issue["severity"]] = severities.get(issue["severity"], 0) + issue["count"]
        progress = data.get("progress") or {}
        trend = progress.get("trend") or []
        # A tiny sparkline has no room to explain changing populations. Show
        # only its latest comparable segment; the overview retains all points.
        segment = []
        for point in trend:
            if point.get("break_before"):
                segment = []
            segment.append(point["score"])
        row.update(scanned=data.get("scanned") or "", summary=data["summary"],
                   issues=severities, trend=segment,
                   changes=[c for c in progress.get("changes") or [] if c.get("comparable")])
        rows.append(row)
    return {"orgs": rows}


if __name__ == "__main__":
    g = build_graph()
    print("nodes:", len(g["nodes"]), "edges:", len(g["edges"]))
    print("summary:", summary())
