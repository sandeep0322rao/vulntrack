import re
from urllib.parse import urlsplit

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import BooleanField, IntegerField, PasswordField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, InputRequired, Length, NumberRange, Optional, ValidationError

from .constants import CATEGORIES, SEVERITIES, STATUSES


def valid_http_url(value):
    try:
        u = urlsplit(value)
        if len(value) > 2048 or u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
            raise ValueError()
        if any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value:
            raise ValueError()
        u.hostname.encode('idna')
        if u.port is not None and not 1 <= u.port <= 65535:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ValueError('Enter a valid HTTP or HTTPS URL without embedded credentials.') from None
    return value


def http_url(form, field):
    try:
        valid_http_url(field.data)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


def email_address(form, field):
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', field.data or ''):
        raise ValidationError('Enter a valid email address.')


class LoginForm(FlaskForm):
    email = StringField('Email address', validators=[DataRequired(), Length(max=254)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=128)])


class UserForm(FlaskForm):
    name = StringField('Full name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Email address', validators=[DataRequired(), Length(max=254), email_address])
    password = PasswordField('Initial password', validators=[DataRequired(), Length(min=12, max=128)])
    role = SelectField('Role', choices=[('tester', 'Security tester'), ('admin', 'Administrator')])


class PasswordForm(FlaskForm):
    current_password = PasswordField('Current password', validators=[DataRequired(), Length(max=128)])
    password = PasswordField('New password', validators=[DataRequired(), Length(min=12, max=128)])
    confirm = PasswordField('Confirm new password', validators=[DataRequired(), EqualTo('password')])


class AssessmentForm(FlaskForm):
    title = StringField('Assessment title', validators=[DataRequired(), Length(max=160)])
    client = StringField('Customer or project', validators=[DataRequired(), Length(max=160)])
    target_url = StringField('Target URL', validators=[DataRequired(), http_url])
    scope = TextAreaField('Authorized scope and exclusions', validators=[DataRequired(), Length(min=10, max=8000)])
    authorization_ref = StringField('Authorization reference', validators=[DataRequired(), Length(max=500)])
    kind = SelectField('Assessment type', choices=[('baseline', 'Baseline assessment'), ('retest', 'Remediation retest')])
    baseline_id = SelectField('Baseline assessment', choices=[], coerce=int, validators=[Optional()])
    authorized = BooleanField('I confirm that this assessment is covered by explicit authorization.', validators=[DataRequired()])


class FindingForm(FlaskForm):
    title = StringField('Finding title', validators=[DataRequired(), Length(max=240)])
    url = StringField('Affected URL', validators=[DataRequired(), http_url])
    method = SelectField('HTTP method', choices=[(x, x) for x in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']])
    parameter = StringField('Parameter', validators=[Optional(), Length(max=160)])
    cwe = StringField('CWE identifier', validators=[Optional(), Length(max=40)])
    severity = SelectField('Severity', choices=[(x, x) for x in SEVERITIES])
    category = SelectField('OWASP Top 10 2025', choices=[('auto', 'Suggest automatically')] + [(k, f'{k} · {v}') for k, v in CATEGORIES.items()])
    confidence = SelectField('Confidence', choices=[(x, x) for x in ['Needs review', 'Low', 'Medium', 'High', 'Confirmed', 'False positive']])
    description = TextAreaField('Description and impact', validators=[DataRequired(), Length(max=12000)])
    evidence = TextAreaField('Evidence', validators=[Optional(), Length(max=12000)])
    remediation = TextAreaField('Remediation guidance', validators=[DataRequired(), Length(max=12000)])
    exploitability = IntegerField('Exploitability', default=50, validators=[InputRequired(), NumberRange(min=0, max=100)])
    business_impact = IntegerField('Business impact', default=50, validators=[InputRequired(), NumberRange(min=0, max=100)])
    exposure = IntegerField('Exposure', default=75, validators=[InputRequired(), NumberRange(min=0, max=100)])


class ImportForm(FlaskForm):
    report = FileField('Excel or scanner report', validators=[FileRequired(), FileAllowed(['xlsx', 'csv', 'json', 'xml'], 'Use an .xlsx, .csv, ZAP .json, or ZAP .xml file.')])
    scope_confirmed = BooleanField('I reviewed this report and confirm it belongs to this assessment scope.', validators=[DataRequired()])


class StatusForm(FlaskForm):
    status = SelectField('Remediation status', choices=list(STATUSES.items()))
    assigned_to = StringField('Assigned to', validators=[Optional(), Length(max=100)])
    resolution_note = TextAreaField('Remediation notes or justification', validators=[Optional(), Length(max=12000)])
    retest_confirmed = BooleanField('I performed the retest and the evidence supports closing this finding.')


class ReportForm(FlaskForm):
    format = SelectField('Report format', choices=[('pdf', 'VAPT PDF report'), ('xlsx', 'Excel workbook')])


class ScanForm(FlaskForm):
    confirmed = BooleanField('I authorize the automatic scan of this approved public URL and understand its coverage.', validators=[DataRequired()])
    active = BooleanField('Include approved active SQL injection and reflected XSS tests')


class ActiveApprovalForm(FlaskForm):
    confirmed = BooleanField('I verified written permission for active testing of this public origin, including automated attack payloads. The recorded scope permits these tests.', validators=[DataRequired()])


class ActionForm(FlaskForm):
    pass


class DeleteForm(FlaskForm):
    confirmation = StringField('Type the exact record title to confirm', validators=[DataRequired(), Length(max=240)])
    current_password = PasswordField('Your current password', validators=[DataRequired(), Length(max=128)])
