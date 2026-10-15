import hashlib
import json
from datetime import timedelta

from ..extensions import db
from ..models import ActiveScanApproval, now


def scope_digest(assessment):
    return hashlib.sha256(json.dumps([assessment.target_url, assessment.scope, assessment.authorization_ref]).encode()).hexdigest()


def active_approval(assessment):
    approval = db.session.scalar(db.select(ActiveScanApproval).where(ActiveScanApproval.assessment_id == assessment.id))
    return approval if approval and assessment.scan_approved and approval.scope_digest == scope_digest(assessment) and approval.created_at >= now() - timedelta(days=7) and approval.approved_by.enabled and approval.approved_by.is_admin else None
