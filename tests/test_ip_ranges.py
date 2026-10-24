"""IP-range scope: validation, API, scanning alongside domains, host ratings."""
import copy
import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import main  # noqa: E402
import scanner  # noqa: E402
import scorecard as sc  # noqa: E402
import cti_correlation as cc  # noqa: E402

AUTH = {"X-CTI-Token": "test-tok"}


# ---------------------------------------------------------------- validation

@pytest.mark.parametrize("raw,canonical", [
    ("5.6.8.9", "5.6.8.9/32"),
    (" 5.6.8.0/24 ", "5.6.8.0/24"),
    ("5.6.8.77/24", "5.6.8.0/24"),          # host bits cleared
    ("5.6.8.4/30", "5.6.8.4/30"),
])
def test_parse_accepts_public_blocks(raw, canonical):
    assert scanner.parse_ip_range(raw) == (canonical, None)


@pytest.mark.parametrize("raw,reason", [
    ("5.6.0.0/20", "more than the limit of 2048"),
    ("10.1.2.0/24", "private"),
    ("100.64.0.0/24", "private"),           # carrier-grade NAT
    ("192.0.2.0/24", "private"),            # documentation range
    ("127.0.0.1", "private"),
    ("2001:4860::/120", "only IPv4"),
    ("example.com", "not an IPv4"),
    ("5.6.8.0/33", "not an IPv4"),
    ("", "empty"),
])
def test_parse_rejects(raw, reason):
    cidr, err = scanner.parse_ip_range(raw)
    assert cidr is None and reason in err


def test_expand_skips_network_and_broadcast_and_dedups():
    assert len(scanner.expand_ip_ranges(["5.6.8.0/24"])) == 254
    assert scanner.expand_ip_ranges(["5.6.8.4/31"]) == ["5.6.8.4", "5.6.8.5"]
    assert scanner.expand_ip_ranges(["5.6.8.4/30", "5.6.8.5"]) == ["5.6.8.5", "5.6.8.6"]
    assert scanner.expand_ip_ranges(["bogus", "10.0.0.1", "5.6.8.9"]) == ["5.6.8.9"]


def test_a_21_is_accepted_by_default():
    assert scanner.MAX_RANGE_IPS == 2048
    assert scanner.parse_ip_range("5.6.8.0/21") == ("5.6.8.0/21", None)
    assert len(scanner.expand_ip_ranges(["5.6.8.0/21"])) == 2046
    ranges, err = scanner.normalize_ip_ranges(["5.6.8.0/22", "5.6.12.0/23"])
    assert err is None and ranges == ["5.6.8.0/22", "5.6.12.0/23"]


def test_limit_is_configurable(monkeypatch):
    monkeypatch.setattr(scanner, "MAX_RANGE_IPS", 4096)
    assert scanner.parse_ip_range("5.6.0.0/20") == ("5.6.0.0/20", None)
    assert len(scanner.expand_ip_ranges(["5.6.0.0/20"])) == 4094
    monkeypatch.setattr(scanner, "MAX_RANGE_IPS", 256)
    assert "more than the limit of 256" in scanner.parse_ip_range("5.6.8.0/23")[1]
    assert len(scanner.expand_ip_ranges(["5.6.8.0/24", "5.6.9.0/24"])) == 256


def test_normalize_enforces_total_and_count_caps(monkeypatch):
    ranges, err = scanner.normalize_ip_ranges(["5.6.8.0/24", "5.6.8.0/24", "5.6.9.1"])
    assert err is None and ranges == ["5.6.8.0/24", "5.6.9.1/32"]
    ranges, err = scanner.normalize_ip_ranges(["5.6.8.0/21", "5.6.16.0/24"])
    assert ranges is None and "ranges cover 2300 addresses" in err
    many = [f"5.6.8.{i}" for i in range(scanner.MAX_RANGES + 1)]
    ranges, err = scanner.normalize_ip_ranges(many)
    assert ranges is None and "too many ranges" in err


# ----------------------------------------------------------------------- API

@pytest.fixture
def workspace(tmp_path, monkeypatch):
    registry = {"acme": {"name": "Acme", "domains": ["example.com"],
                         "findings": "data/orgs/acme/findings.json",
                         "baseline": "data/orgs/acme/baseline.txt"}}
    path = tmp_path / "orgs.json"
    path.write_text(json.dumps(registry))
    monkeypatch.setattr(main, "ORGS_JSON", str(path))
    monkeypatch.setattr(main, "DATA_ORG_DIR", str(tmp_path / "orgs"))
    monkeypatch.setattr(cc, "_REGISTRY_FILE", str(path))
    monkeypatch.setattr(cc, "REGISTRY", copy.deepcopy(registry))
    monkeypatch.setattr(main, "_log_event", lambda *a, **kw: None)
    return TestClient(main.app), path


def test_ranges_add_remove_set_persist(workspace):
    client, path = workspace
    url = "/api/orgs/acme/ip_ranges"
    r = client.post(url, headers=AUTH, json={"ranges": ["5.6.8.77/30", "5.6.9.1"]})
    assert r.status_code == 200
    assert r.json() == {"slug": "acme", "ip_ranges": ["5.6.8.76/30", "5.6.9.1/32"], "addresses": 3}
    assert json.loads(path.read_text())["acme"]["ip_ranges"] == ["5.6.8.76/30", "5.6.9.1/32"]
    assert json.loads(path.read_text())["acme"]["domains"] == ["example.com"]  # untouched
    orgs = client.get("/api/orgs", headers=AUTH).json()["orgs"]
    assert orgs[0]["ip_ranges"] == ["5.6.8.76/30", "5.6.9.1/32"]
    assert client.get("/api/orgs/acme", headers=AUTH).json()["ip_ranges"] == ["5.6.8.76/30", "5.6.9.1/32"]

    r = client.post(url, headers=AUTH, json={"ranges": ["5.6.9.1"], "action": "remove"})
    assert r.json()["ip_ranges"] == ["5.6.8.76/30"]
    r = client.post(url, headers=AUTH, json={"ranges": [], "action": "set"})
    assert r.status_code == 200 and r.json()["ip_ranges"] == []


@pytest.mark.parametrize("body,needle", [
    ({"ranges": ["10.0.0.0/24"]}, "private"),
    ({"ranges": ["5.6.0.0/16"]}, "more than the limit"),
    ({"ranges": ["5.6.8.0/21", "5.6.16.0/24"]}, "more than the limit"),
    ({"ranges": []}, "no ranges"),
    ({"ranges": ["5.6.8.1"], "action": "nuke"}, "invalid action"),
])
def test_invalid_ranges_rejected_without_mutation(workspace, body, needle):
    client, path = workspace
    before = path.read_text()
    r = client.post("/api/orgs/acme/ip_ranges", headers=AUTH, json=body)
    assert r.status_code == 400 and needle in r.json()["error"]
    assert path.read_text() == before


def test_ranges_endpoint_requires_auth_and_known_org(workspace):
    client, _ = workspace
    assert client.post("/api/orgs/acme/ip_ranges", json={"ranges": ["5.6.8.1"]}).status_code == 401
    assert client.post("/api/orgs/ghost/ip_ranges", headers=AUTH,
                       json={"ranges": ["5.6.8.1"]}).status_code == 404


def test_register_with_ranges_only(workspace):
    client, path = workspace
    r = client.post("/api/orgs/register", headers=AUTH,
                    json={"slug": "netops", "ip_ranges": ["5.6.8.0/29"]})
    assert r.status_code == 200, r.text
    assert r.json()["domains"] == [] and r.json()["ip_ranges"] == ["5.6.8.0/29"]
    assert json.loads(path.read_text())["netops"]["ip_ranges"] == ["5.6.8.0/29"]
    bad = client.post("/api/orgs/register", headers=AUTH,
                      json={"slug": "bad", "ip_ranges": ["192.168.0.0/24"]})
    assert bad.status_code == 400 and "bad" not in json.loads(path.read_text())


# ------------------------------------------------------------------ scanning

def _patch_network(monkeypatch, tmp_path, subs, resolve_map, open_by_ip, probed):
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: set(subs))
    monkeypatch.setattr(scanner, "_resolve", lambda h: resolve_map.get(h, []))
    monkeypatch.setattr(scanner, "_fetch_fingerprint", lambda h, timeout, ips: (None, None))

    def tcp(ip, port, timeout):
        probed.add(ip)
        return "reachable" if str(port) in open_by_ip.get(ip, ()) else "closed"
    monkeypatch.setattr(scanner, "_tcp_reachable", tcp)
    # SSH greets first, so an open 22 needs its greeting to count
    monkeypatch.setattr(scanner, "_grab_banner",
                        lambda ip, port, *a, **k: "SSH-2.0-OpenSSH_9.6" if int(port) == 22 else None)
    monkeypatch.setattr(scanner, "_tls_cert", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))


def _org_dir(tmp_path, slug):
    d = tmp_path / "orgs" / slug
    d.mkdir(parents=True)
    (d / "findings.json").write_text(json.dumps({"findings": []}))
    return d


def test_range_ips_scanned_alongside_domains(tmp_path, monkeypatch):
    org_dir = _org_dir(tmp_path, "acme")
    probed = set()
    # app.example.com already resolves to 5.6.8.1, which is inside the range
    _patch_network(monkeypatch, tmp_path, ["app.example.com"], {"app.example.com": ["5.6.8.1"]},
                   {"5.6.8.2": ("22",)}, probed)
    org = {"slug": "acme", "domains": ["example.com"], "ip_ranges": ["5.6.8.0/29"]}
    result = scanner.generate_org(org, mode="fast")
    assert "error" not in result
    assert probed == {"5.6.8.%d" % i for i in range(1, 7)}
    meta = json.loads((org_dir / "findings.json").read_text())["meta"]
    # 5.6.8.1 is scanned under its hostname, not twice
    assert meta["range_hosts"] == ["5.6.8.%d" % i for i in range(2, 7)]
    assert meta["ip_ranges"] == ["5.6.8.0/29"]
    assert meta["subdomains"] == 1
    assert meta["services"]["5.6.8.2"]["open"] == {"22": "ssh"}
    baseline = (org_dir / "baseline.txt").read_text()
    assert "5.6.8.2" in baseline


def test_ranges_only_org_scans(tmp_path, monkeypatch):
    org_dir = _org_dir(tmp_path, "netops")
    probed = set()
    _patch_network(monkeypatch, tmp_path, [], {}, {"5.6.8.9": ("443",)}, probed)
    result = scanner.generate_org({"slug": "netops", "domains": [], "ip_ranges": ["5.6.8.9"]},
                                  mode="fast")
    assert "error" not in result and probed == {"5.6.8.9"}
    meta = json.loads((org_dir / "findings.json").read_text())["meta"]
    assert meta["range_hosts"] == ["5.6.8.9"]


def test_org_without_domains_or_ranges_still_refused():
    with pytest.raises(ValueError):
        scanner.generate_org({"slug": "empty", "domains": [], "ip_ranges": ["10.0.0.1"]})


def test_range_ips_do_not_crowd_out_hostnames(tmp_path, monkeypatch):
    _org_dir(tmp_path, "acme")
    probed = set()
    subs = ["a.example.com", "b.example.com"]
    _patch_network(monkeypatch, tmp_path, subs,
                   {"a.example.com": ["5.6.7.1"], "b.example.com": ["5.6.7.2"]}, {}, probed)
    monkeypatch.setattr(scanner, "MAX_TOTAL_HOSTS", 2)
    scanner.generate_org({"slug": "acme", "domains": ["example.com"],
                          "ip_ranges": ["5.6.8.0/30"]}, mode="fast")
    # IPs sort before names; both hostnames must still be probed
    assert {"5.6.7.1", "5.6.7.2", "5.6.8.1", "5.6.8.2"} <= probed


# -------------------------------------------------------------- host ratings

def test_range_hosts_rated_under_their_range():
    meta = {"ip_ranges": ["5.6.8.0/29"], "range_hosts": ["5.6.8.2", "5.6.8.3"],
            "services": {"5.6.8.2": {"ip": "5.6.8.2", "open": {"3389": "rdp"}},
                         "app.example.com": {"ip": "5.6.7.1", "open": {"443": "https"}}}}
    cards = sc.build_hosts(["example.com"], meta)
    by_host = {c["host"]: c for c in cards}
    assert by_host["5.6.8.2"]["parent"] == "5.6.8.0/29" and by_host["5.6.8.2"]["kind"] == "range"
    assert by_host["app.example.com"]["kind"] == "domain"
    assert "5.6.8.3" not in by_host  # nothing observed there

    rows = cc.hosts_from_snapshot(["example.com"], meta, [])["hosts"]
    row = next(r for r in rows if r["host"] == "5.6.8.2")
    assert row["domain"] == "5.6.8.0/29" and row["kind"] == "range"
    assert row["open_ports"] == ["3389"]
