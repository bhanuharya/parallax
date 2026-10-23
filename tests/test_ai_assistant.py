"""AI providers page and the read-only analyst assistant.

What these tests defend:

  - presets appear only when their credential exists, and a configured
    profile of the same name wins;
  - key VALUES never reach the browser, only variable names;
  - the Codex adapter runs read-only, ephemeral, without the user's config
    and without this server's secrets, and fails closed on timeouts;
  - the agent only reads, checks every citation against the org's data and
    flags CVE ids it invented;
  - the endpoints are auth-gated, validated and concurrency-capped.
"""
import json
import os
import stat
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import ai_providers as ap  # noqa: E402
import assistant  # noqa: E402
import cti_correlation as cc  # noqa: E402


# --------------------------------------------------------------------------
# presets
# --------------------------------------------------------------------------
@pytest.fixture
def no_config(monkeypatch):
    monkeypatch.setattr(ap, "_load_raw_config", lambda: {})
    for env in ("OPENCODE_GO_API_KEY", "OPENCODE_GO_B_API_KEY", "OPENCODE_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(env, raising=False)


def test_presets_need_a_credential(no_config, monkeypatch):
    profiles, _ = ap.load_profiles()
    assert not set(profiles) & set(ap.PRESETS)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    profiles, default = ap.load_profiles()
    assert profiles["deepseek"]["base_url"] == "https://api.deepseek.com"
    assert profiles["deepseek"]["api_key_env"] == "DEEPSEEK_API_KEY"
    assert default == "deepseek"


def test_opencode_go_accepts_the_legacy_key_name(no_config, monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_B_API_KEY", "k")
    prof = ap.load_profiles()[0]["opencode-go"]
    assert prof["api_key_env"] == "OPENCODE_GO_B_API_KEY"
    assert prof["base_url"] == "https://opencode.ai/inference/go/openai/v1"


def test_configured_profile_beats_preset(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(ap, "_validate_base_url", lambda *a: True)
    monkeypatch.setattr(ap, "_load_raw_config", lambda: {"profiles": {"deepseek": {
        "provider": "openai-compatible", "base_url": "https://proxy.example/v1",
        "model": "custom-model", "api_key_env": "DEEPSEEK_API_KEY"}}})
    prof = ap.load_profiles()[0]["deepseek"]
    assert prof["model"] == "custom-model" and not prof.get("preset")


def test_catalog_shows_key_names_never_values(no_config, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-VERY-SECRET-123")
    cat = ap.provider_catalog()
    blob = json.dumps(cat)
    assert "sk-VERY-SECRET-123" not in blob
    rows = {r["id"]: r for r in cat["providers"]}
    assert rows["deepseek"]["connected"] and rows["deepseek"]["key_env"] == "DEEPSEEK_API_KEY"
    assert not rows["opencode-zen"]["connected"] and rows["opencode-zen"]["key_env"] == "OPENCODE_API_KEY"
    assert "glm" not in " ".join(rows)


def test_allowed_models(no_config, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    assert ap.allowed_models("deepseek") == ("deepseek-v4-pro", "deepseek-flash")
    assert ap.allowed_models("missing") == ()


def test_model_override_reaches_the_provider(no_config, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    seen = {}

    def fake(base_url, model, prompt, timeout, key_env, max_tokens=1024, cap_retry=True):
        seen.update(model=model, base_url=base_url)
        return '{"ok": true}', None, {}
    monkeypatch.setattr(ap, "_call_openai_compatible", fake)
    content, prov = ap.call_ai("hi", profile_name="deepseek", model="deepseek-flash")
    assert seen == {"model": "deepseek-flash", "base_url": "https://api.deepseek.com"}
    assert prov["model"] == "deepseek-flash"


# --------------------------------------------------------------------------
# Codex adapter (fake binary: the suite never spends a real plan)
# --------------------------------------------------------------------------
def _fake_codex(tmp_path, body):
    path = tmp_path / "codex"
    path.write_text("#!%s\n" % sys.executable + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


RECORDING_CODEX = """
import json, os, sys
args = sys.argv[1:]
log = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "calls.jsonl")
if args[:2] == ["login", "status"]:
    print("Logged in using ChatGPT (someone@example.com)")
    sys.exit(0)
prompt = sys.stdin.read()
out = args[args.index("-o") + 1]
with open(out, "w") as f:
    f.write('{"ok": true}')
with open(log, "a") as f:
    f.write(json.dumps({"args": args, "prompt": prompt, "cwd": os.getcwd(),
                        "env": sorted(os.environ)}) + "\\n")
"""


@pytest.fixture
def codex(tmp_path, monkeypatch):
    binp = _fake_codex(tmp_path, RECORDING_CODEX)
    monkeypatch.setenv("CTI_CODEX_BIN", binp)
    ap._codex_status_cache.update(at=0.0, value=None)
    yield tmp_path
    ap._codex_status_cache.update(at=0.0, value=None)


def test_codex_preset_follows_the_binary(no_config, codex):
    prof = ap.load_profiles()[0]["codex"]
    assert prof["provider"] == "codex-cli" and prof["model"] == "gpt-6.1-sol"


def test_codex_status_hides_the_account(codex):
    st = ap.codex_login_status()
    assert st["signed_in"] and "@" not in st["method"]


def test_codex_runs_read_only_ephemeral_and_without_secrets(no_config, codex, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-should-not-leak")
    content, prov = ap.call_ai("the prompt", profile_name="codex", model="gpt-6-luna")
    assert content == '{"ok": true}' and prov["provider"] == "codex-cli"
    call = json.loads((codex / "calls.jsonl").read_text().splitlines()[-1])
    args = call["args"]
    assert args[0] == "exec" and args[-1] == "-"
    assert args[args.index("--sandbox") + 1] == "read-only"
    for flag in ("--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check"):
        assert flag in args
    assert args[args.index("-m") + 1] == "gpt-6-luna"
    assert call["prompt"] == "the prompt"
    assert "parallax-codex-" in call["cwd"]
    leaked = [k for k in call["env"] if k.startswith("CTI_") or k.endswith("_API_KEY")]
    assert leaked == []


def test_codex_timeout_and_failure_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_CODEX_BIN", _fake_codex(tmp_path, "import time; time.sleep(30)\n"))
    content, _, diag = ap._call_codex_cli("p", timeout=1)
    assert content is None and "timed out" in diag["error"]
    monkeypatch.setenv("CTI_CODEX_BIN", _fake_codex(
        tmp_path, "import sys; sys.stderr.write('auth failed for a@b.example'); sys.exit(3)\n"))
    content, _, diag = ap._call_codex_cli("p", timeout=10)
    assert content is None and "3" in diag["error"]
    assert "a@b.example" not in diag["response_excerpt"]


# --------------------------------------------------------------------------
# assistant loop
# --------------------------------------------------------------------------
@pytest.fixture
def workspace(tmp_path, monkeypatch):
    fp, hp = tmp_path / "findings.json", tmp_path / "history.json"
    fp.write_text(json.dumps({"meta": {
        "date": "2026-10-23",
        "fingerprints": {"www.example.com": {
            "url": "https://www.example.com", "code": "200", "server": "nginx/1.18.0",
            "versions": [{"product": "nginx", "version": "1.18.0"}], "assets": []}},
        "services": {"www.example.com": {"open": {"3389": "rdp"}}}},
        "findings": [{"id": "F-1", "title": "RDP exposed", "target": "www.example.com",
                      "severity": "HIGH", "status": "OPEN", "related_cves": []}]}))
    hp.write_text("[]")
    monkeypatch.setattr(cc, "REGISTRY", {"acme": {"name": "Acme", "domains": ["example.com"]}})
    monkeypatch.setattr(cc, "_org_paths", lambda slug: (str(fp), None))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    monkeypatch.setattr(cc, "history_path", lambda slug: str(hp))
    cc.invalidate_org_cache("acme")
    yield fp
    cc.invalidate_org_cache("acme")


def scripted(*replies):
    prompts = []
    queue = list(replies)

    def call(prompt):
        prompts.append(prompt)
        reply = queue.pop(0) if queue else '{"answer": "done", "cites": []}'
        return reply, {"provider": "fake", "model": "m", "profile": "p"}
    return call, prompts


def test_tool_then_answer_with_checked_citations(workspace):
    call, prompts = scripted(
        '{"tool": "plan", "args": {"fix": ["port-3389"]}}',
        '```json\n{"answer": "Closing RDP helps. See CVE-2099-0001.", '
        '"cites": ["port-3389", "www.example.com", "nginx@1.18.0", "F-1", "CVE-2021-23017", "evil.example"]}\n```')
    r = assistant.ask("acme", "What should we fix?", "p", call=call)
    assert r["structured"] and r["steps"] == [{"tool": "plan", "args": {"fix": ["port-3389"]}, "ok": True}]
    assert "TOOL RESULT (untrusted data" in prompts[1] and '"after"' in prompts[1]
    verdict = {c["id"]: c["verified"] for c in r["cites"]}
    assert verdict == {"port-3389": True, "www.example.com": True, "nginx@1.18.0": True,
                       "F-1": True, "CVE-2021-23017": True, "evil.example": False}
    assert r["unverified_mentions"] == ["CVE-2099-0001"]


def test_unknown_tool_gets_a_note_and_the_loop_continues(workspace):
    call, prompts = scripted('{"tool": "rm -rf", "args": {}}', '{"answer": "ok", "cites": []}')
    r = assistant.ask("acme", "q", "p", call=call)
    assert r["answer"] == "ok" and "Unknown tool" in prompts[1]


def test_unstructured_replies_still_reach_the_user(workspace):
    call, _ = scripted("I think you should close RDP.", "Really, close RDP.")
    r = assistant.ask("acme", "q", "p", call=call)
    assert r["structured"] is False and "close RDP" in r["answer"]


def test_provider_failure_is_an_error(workspace):
    r = assistant.ask("acme", "q", "p", call=lambda prompt: (None, {"error": "HTTP 401"}))
    assert r["error"] == "HTTP 401"


def test_steps_are_bounded(workspace):
    call, prompts = scripted(*['{"tool": "history", "args": {}}'] * 10)
    r = assistant.ask("acme", "q", "p", call=call)
    assert len(prompts) == assistant.MAX_STEPS
    assert "No more tools are available" in prompts[-1]
    assert len(r["steps"]) == assistant.MAX_STEPS - 1


def test_the_assistant_never_writes(workspace):
    before = workspace.read_bytes()
    call, _ = scripted('{"tool": "plan", "args": {"fix": ["port-3389"]}}',
                       '{"tool": "findings", "args": {"severity": "high"}}',
                       '{"answer": "x", "cites": []}')
    assistant.ask("acme", "q", "p", call=call)
    assert workspace.read_bytes() == before


def test_history_is_bounded_and_included(workspace):
    call, prompts = scripted('{"answer": "x", "cites": []}')
    hist = [{"q": "q%d" % i, "a": "a%d" % i} for i in range(10)]
    assistant.ask("acme", "now?", "p", history=hist, call=call)
    assert "Q: q9" in prompts[0] and "Q: q5" not in prompts[0]


# --------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------
def _client():
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


AUTH = {"X-CTI-Token": "test-tok"}


@pytest.fixture
def deepseek(no_config, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    replies = []

    def fake_call(prompt, profile_name=None, model=None):
        replies.append((profile_name, model))
        return '{"answer": "Close RDP.", "cites": ["port-3389"]}', {
            "provider": "openai-compatible", "model": model or "deepseek-v4-pro", "profile": profile_name}
    monkeypatch.setattr(ap, "call_ai", fake_call)
    return replies


def test_providers_endpoint(deepseek):
    c = _client()
    assert c.get("/api/ai/providers").status_code == 401
    rows = {r["id"]: r for r in c.get("/api/ai/providers", headers=AUTH).json()["providers"]}
    assert rows["deepseek"]["connected"] and "sk-test" not in json.dumps(rows)


def test_assistant_endpoint(workspace, deepseek):
    c = _client()
    url = "/api/orgs/acme/assistant"
    assert c.post(url, json={"question": "q"}).status_code == 401
    assert c.post(url, json={"question": ""}, headers=AUTH).status_code == 400
    assert c.post(url, json={"question": "q", "profile": "nope"}, headers=AUTH).status_code == 400
    assert c.post(url, json={"question": "q", "model": "gpt-everything"}, headers=AUTH).status_code == 400
    r = c.post(url, json={"question": "Fix first?", "profile": "deepseek", "model": "deepseek-flash"},
               headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["answer"] == "Close RDP." and body["cites"][0]["verified"] is True
    assert deepseek[-1] == ("deepseek", "deepseek-flash")


def test_assistant_is_concurrency_capped(workspace, deepseek):
    import main
    held = 0
    while main._AI_SLOTS.acquire(blocking=False):
        held += 1
    try:
        r = _client().post("/api/orgs/acme/assistant", json={"question": "q"}, headers=AUTH)
        assert r.status_code == 429
    finally:
        for _ in range(held):
            main._AI_SLOTS.release()


def test_provider_test_endpoint(deepseek):
    c = _client()
    assert c.post("/api/ai/providers/deepseek/test").status_code == 401
    assert c.post("/api/ai/providers/missing/test", headers=AUTH).status_code == 404
    r = c.post("/api/ai/providers/deepseek/test", headers=AUTH).json()
    assert r["ok"] is False and r["error"] == "unexpected reply"
