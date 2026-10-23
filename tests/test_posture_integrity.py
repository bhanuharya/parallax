"""Regressions for evidence loss masquerading as a posture improvement."""
import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import cve_match
import cti_correlation as cc
import posture
import scanner
import scorecard as sc


def test_service_probe_never_covers_another_domain():
    cards = sc.build(['a.example', 'b.example'], {'services': {'a.example': {'open': {}}}})
    a, b = [next(p for p in c['pillars'] if p['pillar'] == 'exposed') for c in cards]
    assert a['score'] == 100 and not a['unknown']
    assert b['score'] is None and b['unknown']
    assert cards[1]['coverage'] == 0


def test_lost_page_assets_do_not_count_as_verified_improvement():
    web = {'url': 'https://www.example.com', 'code': '200', 'assets': [],
           'strict-transport-security': 'max-age=31536000',
           'content-security-policy': "default-src 'self'", 'x-content-type-options': 'nosniff'}
    meta = {'fingerprints': {'www.example.com': copy.deepcopy(web),
                             'other.example.com': dict(web, url='https://other.example.com')},
            'services': {'www.example.com': {'open': {}}}}
    meta['fingerprints']['www.example.com']['assets'] = [{'kind': 'script', 'host': 'cdn.example.net', 'insecure': True}]
    def snapshot():
        cards = sc.build(['example.com'], meta,
                         cert_rows=[{'host': 'www.example.com', 'issues': []}],
                         dns_results=[{'domain': 'example.com', 'score': 100, 'grade': 'A', 'issues': []}])
        return posture.snapshot(cards, meta)
    old = snapshot()
    del meta['fingerprints']['www.example.com']['assets']
    current = snapshot()
    assert current['domains'][0]['score'] > old['domains'][0]['score']
    events = [event(old), event(current)]
    change = posture.progress(current, events)['changes'][0]
    assert not change['comparable'] and change['delta'] is None
    assert posture.trend(events)[-1]['break_before']


def event(snap):
    return {'kind': 'scan', 'ts': '2026-10-23T09:00:00', 'posture': snap}


def point(a=40, b=100):
    return {'version': posture.MODEL_VERSION, 'domains': [
        {'domain': 'a.example', 'score': a or 0, 'unknown': a is None, 'scope': 'scope-a', 'coverage': 100},
        {'domain': 'b.example', 'score': b, 'unknown': False, 'scope': 'scope-b', 'coverage': 100}]}


def test_trend_breaks_when_bad_domain_becomes_unknown_or_is_removed():
    old = point()
    current = point(None)
    result = posture.trend([event(old), event(current)])
    assert [p['score'] for p in result] == [70, 100]
    assert result[-1]['break_before']
    current['domains'] = current['domains'][1:]
    assert posture.trend([event(old), event(current)])[-1]['break_before']


def test_trend_only_connects_same_population_and_coverage():
    old, current = point(), point(60)
    assert not posture.trend([event(old), event(current)])[-1]['break_before']
    current['domains'][0]['scope'] = 'changed-hosts'
    assert posture.trend([event(old), event(current)])[-1]['break_before']
    missing = {'version': posture.MODEL_VERSION, 'domains': []}
    assert posture.trend([event(old), event(missing), event(old)])[-1]['break_before']


def test_portfolio_does_not_connect_incomparable_scores(monkeypatch):
    monkeypatch.setattr(cc, 'REGISTRY', {'acme': {'name': 'Acme', 'domains': ['a.example', 'b.example']}})
    trend = posture.trend([event(point()), event(point(None)), event(point(None, 90))])
    monkeypatch.setattr(cc, 'scorecard', lambda *a, **kw: {'summary': {}, 'progress': {'trend': trend}})
    assert cc.portfolio()['orgs'][0]['trend'] == [100, 90]


def test_angularjs_advisory_does_not_apply_to_modern_angular():
    for version in ('2.0.0', '15.0.0', '16.1.0', '20.0.0'):
        assert cve_match.match_cves([{'product': 'angular', 'version': version}]) == []
    for product in ('angularjs', 'angular.js', 'angular'):
        result = cve_match.match_cves([{'product': product, 'version': '1.8.3'}])
        assert len(result) == 1
        assert result[0]['cve'] == 'CVE-2023-26116'
        assert result[0]['severity'] == 'MEDIUM' and result[0]['cvss'] == 5.3
        assert result[0]['fix_version'] is None
        assert 'angular.copy()' in result[0]['summary']


def test_stale_angular_finding_cannot_reintroduce_corrected_match():
    meta = {'fingerprints': {'www.example.com': {'versions': [{'product': 'angular', 'version': '15.0.0'}]}}}
    findings = [{'source': 'scan-cve', 'target': 'www.example.com', 'id': 'historical',
                 'related_cves': ['CVE-2023-26116']}]
    row = cc.software_from_meta(meta, findings)[0]
    assert row['related_cves'] == [] and row['cve_count'] == 0
    assert findings[0]['related_cves'] == ['CVE-2023-26116'], 'historical records stay intact'
    assert cc._cve_severity_map()['CVE-2023-26116'] == 'MEDIUM'


def test_scanner_does_not_promote_moderate_advisory(monkeypatch):
    monkeypatch.setattr(scanner, '_existing_target_category_keys', lambda slug: set())
    findings = scanner.synthesize_cve_findings('acme', {'www.example.com': {
        'url': 'https://www.example.com', 'versions': [{'product': 'angularjs', 'version': '1.8.3'}]}})
    assert findings[0]['severity'] == 'MEDIUM'
    assert '16.2.0' not in str(findings[0])
