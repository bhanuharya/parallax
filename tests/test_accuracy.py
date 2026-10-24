"""Accuracy: verified service ports, service-based classification, confidence."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402
import scorecard as sc  # noqa: E402
import cti_correlation as cc  # noqa: E402


# ------------------------------------------------------- protocol from greeting

@pytest.mark.parametrize("banner,expected,proto", [
    ("SSH-2.0-OpenSSH_9.6", "ssh", "ssh"),
    ("HTTP/1.1 400 Bad Request", "ftp", "http"),          # HTTP answering on TCP 21
    ("220 ps90t FTP server ready.", "ftp", "ftp"),
    ("220 mx.example.com ESMTP Postfix", "smtp", "smtp"),
    ("220 ready", "smtp", "smtp"),                        # bare 220: the port decides
    ("+OK POP3 ready", "pop3", "pop3"),
    ("* OK IMAP4rev1 ready", "imap", "imap"),
    ("RFB 003.008", "vnc", "vnc"),
    ("J... | 5.7.44-log....mysql_native_password", "mysql", "mysql"),
    ("Ubuntu 22.04 LTS | server login:", "telnet", "telnet"),
    ("", "ftp", None),
    ("....", "redis", None),
])
def test_identify_protocol(banner, expected, proto):
    assert scanner._identify_protocol(banner, expected) == proto


# --------------------------------------------------------- service verification

def _never(*a, **k):
    raise AssertionError("canaries must not be probed")


def test_silent_greet_first_port_is_unconfirmed_and_web_ports_confirmed():
    services = {"app.example.com": {"ip": "5.6.7.1",
                                    "open": {"21": "ftp", "80": "http", "443": "https"},
                                    "banners": {"80": "HTTP/1.1 301 Moved"}}}
    snippets = {"app.example.com": {"url": "https://app.example.com", "code": "200"}}
    stats = scanner._verify_services(services, snippets, probe=_never)
    svc = services["app.example.com"]
    assert svc["open"] == {"80": "http", "443": "https"}
    assert svc["unconfirmed"] == {"21": {"service": "ftp", "reason": "no-greeting"}}
    assert svc["port_confidence"] == {"80": "high", "443": "high"}
    assert stats == {"blanket_hosts": 0, "unconfirmed_ports": 1}


def test_port_takes_the_protocol_its_greeting_proves():
    services = {"h.example.com": {"ip": "5.6.7.2", "open": {"21": "ftp"},
                                  "banners": {"21": "HTTP/1.1 400 Bad Request"}}}
    scanner._verify_services(services, {}, probe=_never)
    assert services["h.example.com"]["open"] == {"21": "http"}


_MANY = {"23": "telnet", "111": "rpcbind", "139": "netbios-ssn", "445": "smb",
         "1433": "mssql", "3389": "rdp", "5432": "postgresql", "6379": "redis"}


def test_host_answering_canary_ports_is_blanket():
    probed = []

    def probe(ip, port, timeout):
        probed.append(port)
        return "reachable"
    services = {"cdn.example.com": {"ip": "5.6.7.3", "open": dict(_MANY, **{"22": "ssh"}),
                                    "banners": {"22": "SSH-2.0-OpenSSH_9.6"}}}
    stats = scanner._verify_services(services, {}, probe=probe)
    svc = services["cdn.example.com"]
    assert sorted(probed) == sorted(scanner._CANARY_PORTS)
    assert svc["open"] == {"22": "ssh"}                     # the greeting still proves SSH
    assert set(svc["unconfirmed"]) == set(_MANY)
    assert all(u["reason"] == "blanket" for u in svc["unconfirmed"].values())
    assert svc["blanket"]["accepted"] == 3
    assert stats["blanket_hosts"] == 1


def test_real_host_with_many_ports_survives_canaries():
    services = {"db.example.com": {"ip": "5.6.7.4", "open": dict(_MANY), "banners": {}}}
    scanner._verify_services(services, {}, probe=lambda ip, port, t: "closed")
    svc = services["db.example.com"]
    assert svc["open"] == _MANY and "blanket" not in svc
    assert set(svc["port_confidence"].values()) == {"medium"}


def test_canaries_skipped_below_threshold():
    services = {"x.example.com": {"ip": "5.6.7.5", "open": {"3389": "rdp", "445": "smb"}}}
    scanner._verify_services(services, {}, probe=_never)
    assert services["x.example.com"]["open"] == {"3389": "rdp", "445": "smb"}


# ------------------------------------------------- classification by service

@pytest.mark.parametrize("name,cat,sev", [
    ("rdp", "Remote access", "HIGH"), ("ssh", "Remote access", "LOW"),
    ("mysql", "Database", "HIGH"), ("smb", "File sharing", "HIGH"),
    ("ftp", "File sharing", "MEDIUM"), ("smtp", "Mail", "INFO"),
    ("weird", "Network service", "LOW"),
])
def test_classify_service(name, cat, sev):
    _label, c, s, _fix = scanner._classify_service(name, 1)
    assert (c, s) == (cat, sev)


@pytest.fixture
def org_file(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(scanner.cc, "org_findings_path", lambda slug: str(fp))
    return fp


def test_service_finding_ignores_the_hostname(org_file):
    services = {"db-dev.example.com": {"ip": "5.6.7.6", "open": {"21": "ftp"},
                                       "banners": {"21": "220 FTP ready"}}}
    out = scanner.synthesize_surface_findings("sample", {}, [], services)
    f = out[0]
    assert f["title"] == "Exposed FTP service (TCP 21)"
    assert f["category"] == "File sharing" and f["severity"] == "MEDIUM"
    assert f["confidence"] == "high" and f["classified_by"] == "service"
    assert f["evidence"]["name_hint"] == "Development / staging"   # context only
    assert "not used to classify" in f["description"]


def test_web_finding_classified_by_page_content(org_file):
    snippets = {"admin.example.com": {"url": "https://admin.example.com", "code": "200",
                                      "title": "Welcome"},
                "ops.example.com": {"url": "https://ops.example.com", "code": "200",
                                    "title": "Grafana", "tech": ["grafana"]}}
    out = {f["target"]: f for f in scanner.synthesize_surface_findings("sample", snippets, [], {})}
    assert out["admin.example.com"]["category"] == "Web service"
    assert out["admin.example.com"]["severity"] == "INFO"
    assert out["ops.example.com"]["category"] == "Admin / management console"
    assert out["ops.example.com"]["title"] == "Grafana console reachable"


def test_protocol_is_not_a_software_version(org_file):
    assert scanner._banner_versions("HTTP/1.1 404 Not Found") == []
    snippets = {"a.example.com": {"url": "https://a.example.com", "code": "404",
                                  "versions": [{"product": "HTTP", "version": "1.1"}]},
                "b.example.com": {"url": "https://b.example.com", "code": "200",
                                  "versions": [{"product": "nginx", "version": "1.18.0"}]}}
    out = scanner.synthesize_version_findings("sample", snippets)
    assert [f["target"] for f in out] == ["b.example.com"]


# ------------------------------------------------ correcting stored findings

def _legacy_srv(port, name, host="db-dev.example.com", **kw):
    f = {"id": f"SRV-{port}", "title": f"Database service exposed on TCP {port}",
         "category": "Database", "severity": "MEDIUM", "status": "OPEN",
         "source": "scan-services", "target": host, "ip": "5.6.7.7", "port": port,
         "description": f"Open service: {name} on TCP {port}. Classified: Database.",
         "evidence": {"ip": "5.6.7.7", "port": port, "services": {str(port): name}},
         "status_history": []}
    f.update(kw)
    cc.ensure_identity(f)
    return f


def test_unconfirmed_port_findings_become_false_positives():
    services = {"db-dev.example.com": {"ip": "5.6.7.7", "open": {},
                                       "unconfirmed": {"21": {"service": "ftp", "reason": "no-greeting"}}}}
    live = _legacy_srv(21, "ftp")
    owned = _legacy_srv(21, "ftp", status="ACCEPTED_RISK", id="SRV-owned")
    counts = scanner._apply_accuracy_rules([live, owned], services)
    assert counts["false_positive"] == 1
    assert live["status"] == "FALSE_POSITIVE" and live["fp_by"] == "scanner"
    assert "no FTP greeting" in live["fp_reason"] and live["confidence"] == "low"
    assert live["status_history"][-1]["to"] == "FALSE_POSITIVE"
    assert owned["status"] == "ACCEPTED_RISK"               # analyst-owned: untouched


def test_ai_findings_on_blanket_hosts_and_protocol_versions_are_retired():
    services = {"cdn.example.com": {"ip": "5.6.7.8", "open": {}, "blanket": {"accepted": 3}}}
    ai = {"id": "AI-1", "source": "ai-assess", "status": "OPEN", "target": "cdn.example.com",
          "severity": "CRITICAL", "status_history": []}
    ver = {"id": "VER-1", "source": "scan-version", "status": "OPEN", "target": "a.example.com",
           "evidence": {"versions": [{"product": "HTTP", "version": "1.1"}]}, "status_history": []}
    real = {"id": "VER-2", "source": "scan-version", "status": "OPEN", "target": "b.example.com",
            "evidence": {"versions": [{"product": "nginx", "version": "1.18.0"}]}, "status_history": []}
    scanner._apply_accuracy_rules([ai, ver, real], services)
    assert ai["status"] == ver["status"] == "FALSE_POSITIVE"
    assert real["status"] == "OPEN"


def test_legacy_hostname_classification_is_redone_by_service():
    services = {"db-dev.example.com": {"ip": "5.6.7.7", "open": {"22": "ssh"},
                                       "port_confidence": {"22": "high"}}}
    f = _legacy_srv(22, "ssh")
    graded = _legacy_srv(22, "ssh", id="SRV-graded", severity="HIGH", ai_grading={"severity": "HIGH"})
    counts = scanner._apply_accuracy_rules([f, graded], services)
    assert counts["reclassified"] == 2
    assert f["title"] == "Exposed SSH service (TCP 22)"
    assert (f["category"], f["severity"]) == ("Remote access", "LOW")
    assert "Classified" not in f["description"]
    assert f["confidence"] == "high" and f["classified_by"] == "service"
    assert graded["severity"] == "HIGH"                     # AI-graded severity is kept
    again = scanner._apply_accuracy_rules([f], services)
    assert again["reclassified"] == 0                       # idempotent


def test_reconcile_reopens_scanner_false_positive_only_when_port_is_verified():
    f = _legacy_srv(21, "ftp", status="FALSE_POSITIVE", fp_by="scanner", fp_reason="x")
    analyst = _legacy_srv(21, "ftp", id="SRV-a", status="FALSE_POSITIVE", fp_by="analyst")
    scanner._reconcile_findings([f, analyst], {}, {}, [], {})
    assert f["status"] == "FALSE_POSITIVE"                  # still not verified
    services = {"db-dev.example.com": {"ip": "5.6.7.7", "open": {"21": "ftp"}}}
    scanner._reconcile_findings([f, analyst], {}, services, [], {})
    assert f["status"] == "OPEN" and "fp_by" not in f
    assert analyst["status"] == "FALSE_POSITIVE"            # an analyst's call is final


# ------------------------------------------------------------- confidence

@pytest.mark.parametrize("f,level", [
    ({"source": "scan-tls"}, "high"),
    ({"source": "ai-assess"}, "low"),
    ({"source": "scan-enum"}, "low"),
    ({"source": "scan-services", "evidence": {"banners": {"22": "SSH-2.0"}}}, "high"),
    ({"source": "scan-services", "evidence": json.dumps({"port": 3389})}, "medium"),
    ({"source": "scan-headers", "evidence": {"code": "404"}}, "medium"),
    ({"source": "scan-headers", "evidence": {"code": "200"}}, "high"),
    ({"source": "scan-cve", "provenance": {"confidence": "low"}}, "low"),
    ({"source": "baseline-diff", "identity_key": "diff|a.example.com|host"}, "high"),
    ({"source": "scan-services", "confidence": "low", "confidence_reason": "r"}, "low"),
    ({"source": "something-new"}, "medium"),
])
def test_finding_confidence(f, level):
    assert cc.finding_confidence(f)[0] == level


def test_every_list_item_carries_confidence_and_fp_reason():
    f = {"id": "F-1", "title": "t", "severity": "LOW", "status": "FALSE_POSITIVE",
         "source": "scan-services", "target": "a.example.com", "fp_reason": "no greeting"}
    light = cc.normalize_finding_light(f, "sample", meta_date="2026-10-25")
    assert light["confidence"] == "medium" and light["confidence_reason"]
    assert light["fp_reason"] == "no greeting"
    assert cc.canonical_status({"status": "false positive"}) == "FALSE_POSITIVE"


def test_false_positives_leave_the_live_counts():
    fs = [{"status": "OPEN", "severity": "HIGH"}, {"status": "FALSE_POSITIVE", "severity": "HIGH"},
          {"status": "RESOLVED", "severity": "LOW"}]
    s = cc.summary_from_data(fs, [])
    assert s["findings_total"] == 1 and s["false_positive_total"] == 1
    assert s["severity"] == {"HIGH": 1}


# ---------------------------------------------------------- end to end scan

def test_scan_sets_aside_firewall_artifacts_and_ratings_ignore_them(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "acme"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: {"cdn.example.com", "db.example.com"})
    monkeypatch.setattr(scanner, "_resolve", lambda h: {"cdn.example.com": ["5.6.7.9"],
                                                        "db.example.com": ["5.6.7.10"]}.get(h, []))
    monkeypatch.setattr(scanner, "_fetch_fingerprint", lambda h, timeout, ips: (None, None))
    # cdn answers on every port (canaries too); db has a real MySQL and a silent FTP
    monkeypatch.setattr(scanner, "_tcp_reachable", lambda ip, port, timeout:
                        "reachable" if ip == "5.6.7.9" or int(port) in (21, 3306) else "closed")
    monkeypatch.setattr(scanner, "_grab_banner", lambda ip, port, *a, **k:
                        "5.7.44-log mysql_native_password"
                        if ip == "5.6.7.10" and int(port) == 3306 else None)
    monkeypatch.setattr(scanner, "_tls_cert", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))
    scanner.generate_org({"slug": "acme", "domains": ["example.com"]}, mode="fast")
    data = json.loads((org_dir / "findings.json").read_text())
    meta = data["meta"]
    assert meta["services"]["cdn.example.com"]["open"] == {}
    assert meta["services"]["cdn.example.com"]["blanket"]["accepted"] == 3
    assert meta["services"]["db.example.com"]["open"] == {"3306": "mysql"}
    assert meta["service_verification"]["blanket_hosts"] == 1
    srv = [f for f in data["findings"] if f.get("source") == "scan-services"]
    assert [(f["target"], f["port"], f["category"]) for f in srv] == [("db.example.com", 3306, "Database")]
    cards = {c["host"]: c for c in sc.build_hosts(["example.com"], meta)}
    exposed = lambda h: [d["type"] for p in cards[h]["pillars"] if p["pillar"] == "exposed"
                         for d in p["deductions"]]
    assert exposed("cdn.example.com") == []                  # no deduction for artifacts
    assert exposed("db.example.com")                         # the real database still counts
