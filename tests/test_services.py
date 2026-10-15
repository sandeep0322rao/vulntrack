import json
import socket
from datetime import timedelta
from types import SimpleNamespace

import pytest

from vulntrack.extensions import db
from vulntrack.models import Assessment, Finding, ScanJob, now
from vulntrack.services.comparison import compare
from vulntrack.services.intake import add_finding, zap_records
from vulntrack.services.risk import fingerprint, priority, score, suggest_category
from vulntrack.services import scanner


@pytest.mark.parametrize('severity,expected', [('Critical', 100), ('High', 92), ('Medium', 82), ('Low', 72), ('Informational', 64)])
def test_risk_formula(severity, expected):
    assert score(severity, 100, 100, 100) == expected


@pytest.mark.parametrize('inputs', [('Unknown', 50, 50, 50), ('High', -1, 20, 50), ('High', 101, 50, 0), ('High', 5.5, 1, 1)])
def test_risk_invalid_inputs(inputs):
    with pytest.raises(ValueError):
        score(*inputs)


@pytest.mark.parametrize('value,expected', [(0, 'Low'), (39.99, 'Low'), (40, 'Medium'), (59.99, 'Medium'), (60, 'High'), (79.99, 'High'), (80, 'Critical'), (100, 'Critical')])
def test_priority_boundaries(value, expected):
    assert priority(value) == expected


def test_fingerprint_normalization_preserves_resource_case_and_slash():
    assert fingerprint(' SQL  injection ', 'https://EXAMPLE.com:443/Search?b=2&a=1') == fingerprint('sql injection', 'https://example.com/Search?a=1&b=2')
    assert fingerprint('Issue', 'https://example.com/Search') != fingerprint('Issue', 'https://example.com/search')
    assert fingerprint('Issue', 'https://example.com/a/') != fingerprint('Issue', 'https://example.com/a')
    assert suggest_category('x', 'CWE-89')[0] == 'A05:2025'
    assert suggest_category('Unrelated observation')[0] == 'Unmapped'


def test_zap_xml_multiple_instances():
    payload = b'<OWASPZAPReport><site name="https://example.com"><alerts><alertitem><alert>SQL Injection</alert><riskcode>3</riskcode><cweid>89</cweid><desc>Impact</desc><solution>Parameterize</solution><instances><instance><uri>https://example.com/a</uri><method>POST</method><param>id</param></instance><instance><uri>https://example.com/b</uri></instance></instances></alertitem></alerts></site></OWASPZAPReport>'
    rows = zap_records(payload, 'xml')
    assert len(rows) == 2
    assert rows[0]['method'] == 'POST' and rows[0]['severity'] == 'High'
    assert rows[1]['url'].endswith('/b')


def test_comparison_missing_does_not_mean_fixed_and_zero_baseline():
    base = SimpleNamespace(findings=[SimpleNamespace(fingerprint='one', status='open', risk_score=60), SimpleNamespace(fingerprint='two', status='open', risk_score=40)])
    retest = SimpleNamespace(findings=[SimpleNamespace(fingerprint='one', status='remediated', retested_at=now(), risk_score=60), SimpleNamespace(fingerprint='new', status='open', risk_score=20)])
    result = compare(base, retest)
    assert len(result['not_observed']) == 1 and len(result['remediated']) == 1 and len(result['new']) == 1
    assert result['reduction'] == 80
    assert compare(SimpleNamespace(findings=[]), retest)['reduction'] is None


def dns_for(*ips):
    return lambda *args, **kwargs: [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in ips]


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1', '0.0.0.0', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '224.0.0.1'])
def test_private_and_metadata_targets_rejected(monkeypatch, ip):
    monkeypatch.setattr(scanner.socket, 'getaddrinfo', dns_for(ip))
    with pytest.raises(ValueError):
        scanner.validated_target('https://target.example.com')


def test_mixed_dns_answers_and_bad_ports_rejected(monkeypatch):
    monkeypatch.setattr(scanner.socket, 'getaddrinfo', dns_for('93.184.215.14', '10.0.0.5'))
    with pytest.raises(ValueError):
        scanner.validated_target('https://target.example.com')
    with pytest.raises(ValueError):
        scanner.validated_target('http://target.example.com:8080')


def test_public_target_and_pinned_connection(monkeypatch):
    monkeypatch.setattr(scanner.socket, 'getaddrinfo', dns_for('93.184.215.14'))
    assert scanner.validated_target('https://target.example.com')[3] == ['93.184.215.14']
    calls = []
    raw = object()
    monkeypatch.setattr(scanner.socket, 'create_connection', lambda destination, timeout: calls.append(destination) or raw)
    connection = scanner.PinnedHTTPConnection('target.example.com', 80, '93.184.215.14', False, 8)
    connection.connect()
    assert calls == [('93.184.215.14', 80)] and connection.sock is raw


def test_redirects_cannot_escape_approved_origin(monkeypatch):
    monkeypatch.setattr(scanner.socket, 'getaddrinfo', dns_for('93.184.215.14'))
    class Connection:
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pass
        def close(self): pass
        def getresponse(self):
            return SimpleNamespace(status=302, getheaders=lambda: [('Location', 'http://169.254.169.254/latest/meta-data')], getheader=lambda name: 'http://169.254.169.254/latest/meta-data')
    monkeypatch.setattr(scanner, 'PinnedHTTPConnection', Connection)
    with pytest.raises(ValueError, match='approved origin'):
        scanner.fetch('https://target.example.com')


def test_passive_analysis_cookie_values_never_persisted():
    rows = scanner.analyze({'url': 'https://target.example.com', 'headers': [('Content-Type', 'text/html'), ('Set-Cookie', 'session=SUPER_SECRET_VALUE; Path=/')],
                            'body': b'<html><script src="http://cdn.example.com/app.js"></script><form action="http://target.example.com/login"><input type="password"></form></html>'})
    assert any(r['title'] == 'Mixed content references found' for r in rows)
    assert any(r['title'] == 'Password form submits over HTTP' for r in rows)
    assert 'SUPER_SECRET_VALUE' not in json.dumps(rows)
    assert all(r['source'] == 'Passive URL check' for r in rows)


def test_scan_approval_queue_cancellation_worker_and_stale_job(app, signed_in, assessment, monkeypatch):
    signed_in.post(f'/assessments/{assessment.id}/scan', data={'confirmed': 'y'})
    assert db.session.scalar(db.select(db.func.count()).select_from(ScanJob)) == 0
    assessment.scan_approved = True
    db.session.commit()
    signed_in.post(f'/assessments/{assessment.id}/scan', data={'confirmed': 'y'})
    signed_in.post(f'/assessments/{assessment.id}/scan', data={'confirmed': 'y'})
    assert db.session.scalar(db.select(db.func.count()).select_from(ScanJob)) == 1
    job = db.session.scalar(db.select(ScanJob))
    signed_in.post(f'/scans/{job.id}/cancel')
    assert job.status == 'cancelled'
    signed_in.post(f'/assessments/{assessment.id}/scan', data={'confirmed': 'y'})
    monkeypatch.setattr(scanner, 'fetch', lambda *args: {'url': assessment.target_url, 'status': 200, 'headers': [('Content-Type', 'text/html')], 'body': b'<html>Example</html>', 'redirects': []})
    assert scanner.process_next(app)
    completed = db.session.scalar(db.select(ScanJob).where(ScanJob.status == 'completed'))
    assert completed.findings_count > 0 and completed.pages_checked == 1
    assert db.session.scalar(db.select(db.func.count()).select_from(Finding)) == completed.findings_count
    stale = ScanJob(assessment_id=assessment.id, requested_by_id=1, target_url=assessment.target_url, status='running', started_at=now() - timedelta(minutes=6))
    db.session.add(stale)
    db.session.commit()
    scanner.process_next(app)
    assert stale.status == 'failed'


def test_worker_failure_does_not_create_findings(app, assessment, monkeypatch):
    assessment.scan_approved = True
    job = ScanJob(assessment_id=assessment.id, requested_by_id=1, target_url=assessment.target_url)
    db.session.add(job)
    db.session.commit()
    monkeypatch.setattr(scanner, 'fetch', lambda *args: (_ for _ in ()).throw(ValueError('Unsafe redirect rejected')))
    scanner.process_next(app)
    assert job.status == 'failed' and job.error == 'Unsafe redirect rejected'
    assert db.session.scalar(db.select(db.func.count()).select_from(Finding)) == 0


def test_queue_prevents_duplicate_active_jobs_at_database_level(app, assessment):
    from sqlalchemy.exc import IntegrityError
    db.session.add(ScanJob(assessment_id=assessment.id, requested_by_id=1, target_url=assessment.target_url))
    db.session.commit()
    db.session.add(ScanJob(assessment_id=assessment.id, requested_by_id=1, target_url=assessment.target_url))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
