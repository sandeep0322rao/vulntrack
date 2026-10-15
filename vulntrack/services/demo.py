from datetime import timedelta

from ..extensions import db
from ..models import Assessment, AuditLog, now
from .intake import add_finding


def seed(user):
    if db.session.scalar(db.select(Assessment).where(Assessment.owner_id == user.id, Assessment.client == 'Northstar Demo · Synthetic')):
        return False
    base = Assessment(owner_id=user.id, title='Customer portal · Baseline', client='Northstar Demo · Synthetic',
                      target_url='https://portal.example.com', scope='Synthetic customer portal demonstration. No live scans are authorized or performed.',
                      authorization_ref='DEMO-ONLY · synthetic data', created_at=now() - timedelta(days=14))
    db.session.add(base)
    db.session.flush()
    retest = Assessment(owner_id=user.id, title='Customer portal · Retest', client=base.client, target_url=base.target_url,
                        scope=base.scope, authorization_ref=base.authorization_ref, kind='retest', baseline_id=base.id)
    db.session.add(retest)
    db.session.flush()
    examples = [
        ('SQL injection in search parameter', 'High', '89', '/search', 'q'),
        ('Broken object access control', 'Critical', '639', '/api/invoices/104', 'id'),
        ('Content Security Policy header missing', 'Low', '693', '/', ''),
        ('Session cookie without Secure flag', 'Medium', '614', '/login', ''),
        ('Reflected cross-site scripting', 'High', '79', '/products', 'query'),
        ('Information disclosure in error response', 'Low', '209', '/api/items', ''),
        ('Outdated JavaScript dependency', 'Medium', '1104', '/assets/app.js', ''),
        ('Missing authentication rate limiting', 'Medium', '307', '/login', ''),
        ('Cross-site request forgery on profile update', 'Medium', '352', '/account', ''),
        ('Weak TLS configuration', 'Medium', '327', '/', ''),
        ('Security logging coverage requires review', 'Informational', '778', '/admin', ''),
        ('Verbose server header', 'Informational', '200', '/', ''),
        ('Insecure file upload validation', 'High', '434', '/upload', 'file'),
        ('Session expiration not enforced', 'High', '613', '/account', ''),
        ('Unvalidated redirect parameter', 'Low', '601', '/redirect', 'next'),
    ]
    for i, (title, severity, cwe, path, parameter) in enumerate(examples):
        data = dict(title=title, severity=severity, cwe=cwe, url=base.target_url + path, parameter=parameter, method='GET',
                    source='Synthetic demo', confidence='Needs review', description=f'Synthetic demonstration finding #{i + 1}. This is sample data, not a customer vulnerability.',
                    evidence='DEMONSTRATION ONLY. No real requests, tokens, or customer evidence.',
                    remediation='Review the affected control, implement an appropriate fix, and record retest evidence.',
                    exploitability=80 if severity in ('Critical', 'High') else 45, business_impact=90 if i < 2 else 55, exposure=85)
        f = add_finding(base, data)
        if i in (0, 1, 4):
            f.assigned_to = 'Application team'
            f.status = 'in_progress'
        elif i == 7:
            f.status = 'ready_retest'
            f.assigned_to = 'Security team'
        if i < 9:
            r = add_finding(retest, data)
            if i < 6:
                r.status, r.retested_at, r.retested_by_id = 'remediated', now(), user.id
                r.resolution_note = 'Synthetic retest evidence confirms the demonstration fix.'
            elif i == 8:
                r.status = 'accepted_risk'
                r.resolution_note = 'Demo risk acceptance until replacement release. Owner review due in 30 days.'
    add_finding(retest, dict(title='Overly permissive CORS configuration', url=base.target_url + '/api', severity='Medium', cwe='942',
                            source='Synthetic demo', confidence='Needs review', description='New synthetic finding in the retest assessment.',
                            evidence='DEMONSTRATION ONLY.', remediation='Restrict origins according to the API trust model.'))
    db.session.add(AuditLog(actor_id=user.id, assessment_id=base.id, action='synthetic_demo_seeded', details='25 synthetic findings across baseline and retest; no live scans'))
    db.session.commit()
    return True
