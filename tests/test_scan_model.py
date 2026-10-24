"""AI-assisted scans can run on a chosen model of the profile (e.g. a flash model)."""
import json
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import ai_providers as ap  # noqa: E402
import cti_correlation as cc  # noqa: E402
import main  # noqa: E402
import scanner  # noqa: E402

AUTH = {"X-CTI-Token": "test-tok"}


@pytest.fixture
def opencode_go(tmp_path, monkeypatch):
    """Only the OpenCode Go preset is connected; one registered org."""
    for k in ("CTI_AI_CONFIG", "CTI_AI_BASE_URL", "CTI_AI_MODEL", "DEEPSEEK_API_KEY",
              "OPENCODE_API_KEY", "OPENCODE_GO_B_API_KEY", "HERMES_CUSTOM_API_CLINE_BOT_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CTI_AI_CONFIG_FILE", str(tmp_path / "ai_config.json"))
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "test-key")
    monkeypatch.setattr(ap, "codex_bin", lambda: None)
    registry = {"acme": {"name": "Acme", "domains": ["example.com"]}}
    (tmp_path / "orgs.json").write_text(json.dumps(registry))
    monkeypatch.setattr(main, "ORGS_JSON", str(tmp_path / "orgs.json"))
    monkeypatch.setattr(cc, "_REGISTRY_FILE", str(tmp_path / "orgs.json"))
    monkeypatch.setattr(cc, "REGISTRY", registry)
    monkeypatch.setattr(ap, "ORG_PROFILES_PATH", str(tmp_path / "ai_org_profiles.json"))
    monkeypatch.setattr(main, "_log_event", lambda *a, **k: None)
    main._jobs.clear()
    return TestClient(main.app)


def _wait(client, jid):
    for _ in range(200):
        r = client.get(f"/api/orgs/acme/scan/{jid}", headers=AUTH)
        if r.status_code == 200 and r.json().get("status") in ("done", "failed"):
            return r.json()
        time.sleep(0.02)
    raise AssertionError("scan job did not finish")


@pytest.mark.parametrize("url", ["/api/ai/profiles", "/api/ai/capabilities"])
def test_flash_models_are_offered_for_the_profile(opencode_go, url):
    # the scan card loads /api/ai/profiles first and only falls back to
    # capabilities, so both views must carry the model list
    caps = opencode_go.get(url, headers=AUTH).json()
    prof = next(p for p in caps["profiles"] if p["name"] == "opencode-go")
    assert {"glm-5.3-flash", "deepseek-v4.1-flash"} <= set(prof["models"])


@pytest.mark.parametrize("model", ["glm-5.3-flash", "deepseek-v4.1-flash"])
def test_ai_scan_runs_on_the_chosen_model(opencode_go, monkeypatch, model):
    seen = {}

    def fake_generate(org, mode="fast", ai_profile=None, on_progress=None, ai_model=None):
        seen.update(mode=mode, ai_profile=ai_profile, ai_model=ai_model)
        return {"slug": "acme", "ai": "done"}
    monkeypatch.setattr(scanner, "generate_org", fake_generate)
    r = opencode_go.post("/api/orgs/acme/scan", headers=AUTH,
                         json={"mode": "ai", "ai_profile": "opencode-go", "model": model})
    assert r.status_code == 200 and r.json()["model"] == model
    assert _wait(opencode_go, r.json()["job_id"])["status"] == "done"
    assert seen == {"mode": "ai", "ai_profile": "opencode-go", "ai_model": model}


def test_unknown_model_is_refused_before_queuing(opencode_go, monkeypatch):
    monkeypatch.setattr(scanner, "generate_org", lambda *a, **k: pytest.fail("must not scan"))
    r = opencode_go.post("/api/orgs/acme/scan", headers=AUTH,
                         json={"mode": "ai", "ai_profile": "opencode-go", "model": "gpt-everything"})
    assert r.status_code == 400
    assert "glm-5.3-flash" in r.json()["allowed"]


def test_fast_scan_ignores_a_model(opencode_go, monkeypatch):
    seen = {}
    monkeypatch.setattr(scanner, "generate_org",
                        lambda org, mode="fast", ai_profile=None, on_progress=None, **kw:
                        seen.update(kw) or {"slug": "acme"})
    r = opencode_go.post("/api/orgs/acme/scan", headers=AUTH,
                         json={"mode": "fast", "model": "gpt-everything"})
    assert r.status_code == 200 and r.json()["model"] is None
    _wait(opencode_go, r.json()["job_id"])
    assert seen == {}


def test_triage_and_grading_send_the_model_to_the_provider(monkeypatch):
    calls = []

    def fake_call(prompt, profile_name=None, model=None):
        calls.append((profile_name, model))
        return '{"results": []}', {"profile": profile_name, "model": model}
    monkeypatch.setattr(scanner.ai_providers, "call_ai", fake_call)
    scanner.ai_assess_finding({"vpn.example.com": {"code": "200"}}, ["vpn.example.com"],
                              profile_name="opencode-go", model="deepseek-v4.1-flash")
    assert calls == [("opencode-go", "deepseek-v4.1-flash")]
    calls.clear()
    scanner.ai_assess_finding({"vpn.example.com": {"code": "200"}}, ["vpn.example.com"],
                              profile_name="opencode-go")
    assert calls == [("opencode-go", None)]                 # no model: profile default
