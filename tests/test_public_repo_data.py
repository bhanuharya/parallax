"""The tracked data files are public: they may only describe example orgs.

Real registrations belong in CTI_DATA_DIR outside the checkout. A real org
slipped into data/orgs.json once (two client domains, one with OpenHack
enabled); this keeps the tracked copy sample-only.
"""
import json
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
# RFC 2606 / RFC 6761 names reserved for documentation and testing
_RESERVED = (".example", ".test", ".invalid", ".localhost", "example.com", "example.net", "example.org")


def _reserved(domain):
    d = str(domain).lower().rstrip(".")
    return any(d == r.lstrip(".") or d.endswith(r if r.startswith(".") else "." + r) or d == r
               for r in _RESERVED)


def test_tracked_registry_lists_only_example_orgs():
    with open(os.path.join(ROOT, "data", "orgs.json")) as f:
        registry = json.load(f)
    for slug, org in registry.items():
        for domain in org.get("domains") or []:
            assert _reserved(domain), "real domain %r for %r in tracked data/orgs.json" % (domain, slug)
        assert not org.get("openhack_enabled"), "active testing enabled in the tracked registry: %r" % slug


def test_tracked_baselines_and_findings_are_not_committed():
    ignored = open(os.path.join(ROOT, ".gitignore")).read()
    for rule in ("data/orgs/", "data/*findings*.json", "data/*baseline*.txt"):
        assert rule in ignored, "scan output must stay ignored: %s" % rule
