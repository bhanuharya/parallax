"""Renames preserve org identity, persisted scope and neighboring workspaces."""
import copy
import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import main
import cti_correlation as cc

AUTH = {"X-CTI-Token": "test-tok"}


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    registry = {
        "acme": {"name": "Acme", "domains": ["example.com"],
                 "findings": "data/orgs/acme/findings.json", "baseline": "data/orgs/acme/baseline.txt"},
        "beta": {"name": "Beta", "domains": ["example.net"], "custom": {"kept": True}},
    }
    path = tmp_path / "orgs.json"
    path.write_text(json.dumps(registry))
    monkeypatch.setattr(main, "ORGS_JSON", str(path))
    monkeypatch.setattr(cc, "_REGISTRY_FILE", str(path))
    monkeypatch.setattr(cc, "REGISTRY", copy.deepcopy(registry))
    monkeypatch.setattr(main, "_log_event", lambda *a, **kw: None)
    return TestClient(main.app), path, registry


def test_rename_persists_and_preserves_identity(workspace):
    client, path, original = workspace
    name = 'PT Example & Partners — 日本'
    response = client.patch('/api/orgs/acme', headers=AUTH, json={"name": '  ' + name + '  '})
    assert response.status_code == 200
    assert response.json() == {"slug": "acme", "name": name}
    expected = copy.deepcopy(original)
    expected['acme']['name'] = name
    assert json.loads(path.read_text()) == expected
    # Reload simulates restarting the registry reader.
    cc._reload_registry()
    assert cc.org_get('acme')['name'] == name
    assert client.get('/api/orgs', headers=AUTH).json()['orgs'][0]['name'] == name
    portfolio = client.get('/api/portfolio', headers=AUTH).json()['orgs']
    assert next(o for o in portfolio if o['slug'] == 'acme')['name'] == name
    report = client.get('/api/orgs/acme/report.html', headers=AUTH)
    assert report.status_code == 200
    assert 'PT Example &amp; Partners — 日本' in report.text
    assert client.patch('/api/orgs/acme', headers=AUTH, json={"name": name}).status_code == 200
    assert json.loads(path.read_text()) == expected


@pytest.mark.parametrize('payload,status', [
    ({"name": ""}, 400), ({"name": "  "}, 400), ({"name": 'x' * 201}, 400),
    ({"name": "Name\nInjected line"}, 400), ({"name": "Bad\x00name"}, 400),
    ({"name": None}, 422), ({}, 422), ({"name": "New", "slug": "other"}, 422),
])
def test_invalid_names_do_not_mutate_registry(workspace, payload, status):
    client, path, original = workspace
    before = path.read_bytes()
    assert client.patch('/api/orgs/acme', headers=AUTH, json=payload).status_code == status
    assert path.read_bytes() == before and cc.REGISTRY == original


def test_rename_requires_auth_and_existing_org(workspace):
    client, path, _ = workspace
    before = path.read_bytes()
    assert client.patch('/api/orgs/acme', json={"name": "New"}).status_code == 401
    assert client.patch('/api/orgs/missing', headers=AUTH, json={"name": "New"}).status_code == 404
    assert path.read_bytes() == before


def test_rename_refuses_corrupted_registry(workspace):
    client, path, original = workspace
    path.write_text('not valid json')
    assert client.patch('/api/orgs/acme', headers=AUTH, json={"name": "New"}).status_code == 500
    assert path.read_text() == 'not valid json' and cc.REGISTRY == original


def test_rename_write_failure_preserves_memory_and_disk(workspace, monkeypatch):
    client, path, original = workspace
    def fail(*args):
        raise OSError('disk unavailable')
    monkeypatch.setattr(cc, '_atomic_write_json', fail)
    assert client.patch('/api/orgs/acme', headers=AUTH, json={"name": "New"}).status_code == 500
    assert json.loads(path.read_text()) == original and cc.REGISTRY == original
