import secrets
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(254), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='tester')
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    auth_token = db.Column(db.String(64), nullable=False, default=lambda: secrets.token_hex(24))
    created_at = db.Column(db.DateTime, nullable=False, default=now)

    @property
    def is_active(self):
        return self.enabled

    @property
    def is_admin(self):
        return self.role == 'admin'

    def get_id(self):
        return f'{self.id}:{self.auth_token}'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='scrypt')
        self.auth_token = secrets.token_hex(24)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    owner = db.relationship('User', foreign_keys=[owner_id])
    title = db.Column(db.String(160), nullable=False)
    client = db.Column(db.String(160), nullable=False)
    target_url = db.Column(db.String(2048), nullable=False)
    scope = db.Column(db.Text, nullable=False)
    authorization_ref = db.Column(db.String(500), nullable=False)
    kind = db.Column(db.String(20), nullable=False, default='baseline')
    baseline_id = db.Column(db.Integer, db.ForeignKey('assessment.id'))
    baseline = db.relationship('Assessment', remote_side=[id])
    scan_approved = db.Column(db.Boolean, nullable=False, default=False)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    approved_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    updated_at = db.Column(db.DateTime, nullable=False, default=now, onupdate=now)
    findings = db.relationship('Finding', back_populates='assessment', lazy='select')


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    assessment = db.relationship('Assessment', back_populates='findings')
    title = db.Column(db.String(240), nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    method = db.Column(db.String(10), nullable=False, default='GET')
    parameter = db.Column(db.String(160), nullable=False, default='')
    cwe = db.Column(db.String(40), nullable=False, default='')
    severity = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.String(30), nullable=False, default='Needs review')
    category = db.Column(db.String(20), nullable=False, default='Unmapped')
    mapping_reason = db.Column(db.String(500), nullable=False, default='Manual classification')
    description = db.Column(db.Text, nullable=False, default='')
    evidence = db.Column(db.Text, nullable=False, default='')
    remediation = db.Column(db.Text, nullable=False, default='')
    source = db.Column(db.String(80), nullable=False, default='Manual')
    exploitability = db.Column(db.Integer, nullable=False, default=50)
    business_impact = db.Column(db.Integer, nullable=False, default=50)
    exposure = db.Column(db.Integer, nullable=False, default=75)
    risk_score = db.Column(db.Float, nullable=False, default=0)
    fingerprint = db.Column(db.String(64), nullable=False, index=True)
    duplicate_of_id = db.Column(db.Integer, db.ForeignKey('finding.id'))
    duplicate = db.relationship('Finding', remote_side=[id])
    status = db.Column(db.String(30), nullable=False, default='open', index=True)
    assigned_to = db.Column(db.String(100), nullable=False, default='')
    resolution_note = db.Column(db.Text, nullable=False, default='')
    retested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    retested_by = db.relationship('User')
    retested_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    updated_at = db.Column(db.DateTime, nullable=False, default=now, onupdate=now)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    actor = db.relationship('User')
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), index=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(1000), nullable=False, default='')
    created_at = db.Column(db.DateTime, nullable=False, default=now)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    assessment = db.relationship('Assessment')
    generated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    generated_by = db.relationship('User')
    format = db.Column(db.String(10), nullable=False)
    filename = db.Column(db.String(160), nullable=False)
    snapshot = db.Column(db.JSON, nullable=False)
    content = db.Column(db.LargeBinary, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)


class ScanJob(db.Model):
    __table_args__ = (db.Index('uq_active_scan_assessment', 'assessment_id', unique=True,
                              sqlite_where=db.text("status IN ('queued', 'running')"),
                              postgresql_where=db.text("status IN ('queued', 'running')")),)
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    assessment = db.relationship('Assessment')
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='queued', index=True)
    target_url = db.Column(db.String(2048), nullable=False)
    pages_checked = db.Column(db.Integer, nullable=False, default=0)
    findings_count = db.Column(db.Integer, nullable=False, default=0)
    cancel_requested = db.Column(db.Boolean, nullable=False, default=False)
    error = db.Column(db.String(1000), nullable=False, default='')
    result = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_key = db.Column(db.String(64), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now, index=True)


class ImportBatch(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: secrets.token_hex(16))
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, index=True)
    assessment = db.relationship('Assessment')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(160), nullable=False)
    format = db.Column(db.String(10), nullable=False)
    records = db.Column(db.JSON, nullable=False)
    errors = db.Column(db.JSON, nullable=False)
    warnings = db.Column(db.JSON, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    committed_at = db.Column(db.DateTime)


class ActiveScanApproval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False, unique=True)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by = db.relationship('User')
    scope_digest = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
