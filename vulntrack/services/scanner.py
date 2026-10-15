"""Bounded passive response analysis, without exploit payloads or form submission.

Every connection is pinned to an already validated public IP. HTTPS retains the
original hostname for SNI and certificate verification. Redirects are checked
again and confined to the approved exact origin. Environment proxies are unused.
"""
import http.client
import ipaddress
import socket
import ssl
import time
from datetime import timedelta
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from ..extensions import db
from ..forms import valid_http_url
from ..models import AuditLog, ImportBatch, ScanJob, now
from .intake import add_finding

MAX_BODY = 1024 * 1024
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = 8


def validated_target(url):
    valid_http_url(url)
    parsed = urlsplit(url)
    host = parsed.hostname.encode('idna').decode('ascii').lower().rstrip('.')
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if port not in (80, 443):
        raise ValueError('Only public HTTP/HTTPS targets on ports 80 and 443 are allowed.')
    if host in ('localhost', 'metadata.google.internal') or host.endswith(('.localhost', '.local', '.internal', '.test', '.invalid', '.example')):
        raise ValueError('Local, reserved, and internal destinations are blocked.')
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise ValueError('The target hostname could not be resolved.') from exc
    ips = list(dict.fromkeys(item[4][0] for item in addresses))
    if not ips:
        raise ValueError('No public destination was resolved.')
    for value in ips:
        address = ipaddress.ip_address(value)
        mapped = getattr(address, 'ipv4_mapped', None)
        if not address.is_global or address.is_multicast or address.is_unspecified or (mapped and not mapped.is_global):
            raise ValueError('The target resolves to a private, loopback, reserved, or non-public address.')
        # Reject IPv6 transition mechanisms that embed a second destination.
        if address.version == 6 and (address.sixtofour or address.teredo):
            raise ValueError('IPv6 transition addresses are not allowed.')
    return parsed, host, port, ips


def origin(url):
    parsed = urlsplit(url)
    return parsed.scheme.lower(), parsed.hostname.encode('idna').decode().lower().rstrip('.'), parsed.port or (443 if parsed.scheme == 'https' else 80)


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ip, secure, timeout):
        super().__init__(host, port, timeout=timeout)
        self.ip = ip
        self.secure = secure

    def connect(self):
        raw = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        try:
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host) if self.secure else raw
        except BaseException:
            raw.close()
            raise


def fetch(url, cancelled=lambda: False, deadline=None):
    deadline = deadline or time.monotonic() + 60
    approved_origin = origin(url)
    current = url
    history = []
    for _ in range(MAX_REDIRECTS + 1):
        if cancelled():
            raise InterruptedError('Scan cancelled.')
        if time.monotonic() >= deadline:
            raise TimeoutError('Scan time limit reached.')
        if origin(current) != approved_origin:
            raise ValueError('A redirect left the approved origin. Update the assessment URL and obtain approval for the new target.')
        parsed, host, port, ips = validated_target(current)
        connection = PinnedHTTPConnection(host, port, ips[0], parsed.scheme == 'https', min(REQUEST_TIMEOUT, max(.1, deadline - time.monotonic())))
        try:
            path = urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
            # Encode non-ASCII URL paths without interpreting user input as headers.
            from urllib.parse import quote
            path = quote(path, safe='/%?=&:+,;@!$\'()*~-._')
            connection.request('GET', path, headers={'User-Agent': 'VulnTrack-Passive/1.0 (authorized assessment)', 'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1', 'Accept-Encoding': 'identity', 'Connection': 'close'})
            response = connection.getresponse()
            headers = response.getheaders()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    raise ValueError('The target returned a redirect without a destination.')
                history.append(current)
                current = urljoin(current, location)
                valid_http_url(current)
                continue
            if response.status >= 400:
                raise ValueError(f'The target returned HTTP {response.status}; no complete page assessment was performed.')
            if response.status == 204:
                raise ValueError('The target returned no content.')
            encoding = response.getheader('Content-Encoding', '').lower()
            if encoding not in ('', 'identity'):
                raise ValueError('The target ignored the uncompressed response request; compressed content is not processed by this bounded check.')
            body = bytearray()
            while True:
                if cancelled():
                    raise InterruptedError('Scan cancelled.')
                if time.monotonic() >= deadline:
                    raise TimeoutError('Scan time limit reached.')
                chunk = response.read(16384)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > MAX_BODY:
                    raise ValueError('Response exceeds the 1 MB limit; the check was stopped.')
            return {'url': current, 'status': response.status, 'headers': headers, 'body': bytes(body), 'redirects': history}
        finally:
            connection.close()
    raise ValueError('More than three redirects were required; no complete check was performed.')


def analyze(response):
    url = response['url']
    headers = {key.lower(): value for key, value in response['headers']}
    secure = urlsplit(url).scheme == 'https'
    records = []

    def add(title, severity, evidence, remediation, cwe, description, confidence='Medium'):
        records.append(dict(title=title, url=url, method='GET', severity=severity, evidence=evidence[:12000],
                            remediation=remediation, cwe=cwe, description=description, source='Passive URL check', confidence=confidence))

    if not secure:
        add('Unencrypted HTTP response', 'Medium', 'The final response was delivered over HTTP.', 'Serve this resource over HTTPS and redirect HTTP traffic to the approved HTTPS origin.', '319', 'Traffic on this resource is not protected by TLS. No credentials were submitted.')
    if secure and 'strict-transport-security' not in headers:
        add('Strict Transport Security header missing', 'Low', 'Strict-Transport-Security was absent on the checked HTTPS response.', 'Evaluate and deploy an appropriate HSTS policy after confirming HTTPS coverage.', '693', 'Browsers are not instructed by this response to enforce future HTTPS access.')
    html = 'html' in headers.get('content-type', '').lower()
    if html:
        csp = headers.get('content-security-policy', '')
        if not csp:
            add('Content Security Policy header missing', 'Low', 'Content-Security-Policy was absent on the checked HTML response.', 'Develop and test a restrictive CSP appropriate to this application.', '693', 'A defense-in-depth browser policy is missing. This observation alone does not establish XSS.')
        if 'x-frame-options' not in headers and 'frame-ancestors' not in csp.lower():
            add('Framing protection not observed', 'Low', 'Neither X-Frame-Options nor CSP frame-ancestors was observed.', 'Set CSP frame-ancestors and, where appropriate, X-Frame-Options.', '1021', 'The checked page may be embeddable. A tester should assess clickjacking impact.', 'Low')
        if 'referrer-policy' not in headers:
            add('Explicit Referrer Policy missing', 'Informational', 'No Referrer-Policy response header was observed; browser defaults may apply.', 'Set an explicit policy consistent with your privacy requirements.', '200', 'Review referrer behavior where URL paths or queries contain sensitive information.', 'Low')
    if headers.get('x-content-type-options', '').lower() != 'nosniff':
        add('Content type sniffing protection missing', 'Low', 'X-Content-Type-Options: nosniff was not observed.', 'Return correct Content-Type values and add X-Content-Type-Options: nosniff.', '693', 'The response does not explicitly disable MIME type sniffing.')
    for key, value in response['headers']:
        if key.lower() == 'set-cookie':
            cookies = SimpleCookie()
            try:
                cookies.load(value)
            except CookieError:
                continue
            for name, cookie in cookies.items():
                # Never persist cookie values in scan evidence.
                if secure and not cookie['secure']:
                    add('Cookie without Secure attribute', 'Low', f'Cookie {name[:120]} lacks Secure. Value omitted.', 'Use Secure on cookies that should only travel over HTTPS.', '614', 'This cookie may be sent over an unencrypted connection if its scope permits it.')
                if not cookie['httponly']:
                    add('Cookie without HttpOnly attribute', 'Low', f'Cookie {name[:120]} lacks HttpOnly. Value omitted.', 'Use HttpOnly for session and sensitive cookies that do not require JavaScript access.', '1004', 'Review whether this cookie contains sensitive state. Some cookies intentionally require script access.', 'Low')
                if not cookie['samesite']:
                    add('Cookie without explicit SameSite attribute', 'Informational', f'Cookie {name[:120]} has no explicit SameSite. Value omitted.', 'Set an appropriate SameSite policy and retain server-side CSRF defenses.', '1275', 'Browser defaults vary. An absent attribute is not proof of exploitable CSRF.', 'Low')
    if html:
        soup = BeautifulSoup(response['body'], 'html.parser')
        if secure:
            mixed = [str(tag.get('src') or tag.get('href'))[:300] for tag in soup.find_all(['script', 'iframe', 'img', 'link', 'audio', 'video']) if str(tag.get('src') or tag.get('href') or '').lower().startswith('http://')]
            if mixed:
                add('Mixed content references found', 'Medium', '\n'.join(mixed[:12]), 'Use HTTPS for subresources and confirm browser behavior.', '319', 'The HTTPS page references HTTP subresources. Browsers may block or upgrade some references.')
        for form in soup.find_all('form')[:20]:
            if form.find('input', attrs={'type': lambda value: value and value.lower() == 'password'}):
                action = urljoin(url, form.get('action') or url)
                if urlsplit(action).scheme == 'http':
                    add('Password form submits over HTTP', 'High', f'Form action: {action[:500]}. No form was submitted.', 'Submit login forms exclusively to HTTPS endpoints.', '319', 'The form advertises an unencrypted destination for password submission.')
    # Consolidate observations with the same title; retain multiple evidence lines.
    unique = {}
    for record in records:
        if record['title'] in unique:
            unique[record['title']]['evidence'] = (unique[record['title']]['evidence'] + '\n' + record['evidence'])[:12000]
        else:
            unique[record['title']] = record
    return list(unique.values())


def process_next(app):
    db.session.execute(db.update(ImportBatch).where(ImportBatch.status == 'pending', ImportBatch.created_at < now() - timedelta(minutes=30)).values(status='expired', records=[], errors=[], warnings=[]))
    # Interrupted workers do not silently leave jobs running forever.
    stale = db.session.scalars(db.select(ScanJob).where(ScanJob.status == 'running', ScanJob.started_at < now() - timedelta(minutes=5))).all()
    for job in stale:
        if (job.result or {}).get('profile') == 'active' and job.started_at >= now() - timedelta(minutes=10):
            continue
        job.status, job.finished_at, job.error = 'failed', now(), 'Worker interrupted or scan exceeded its execution window. Review and queue a new check.'
        db.session.add(AuditLog(actor_id=job.requested_by_id, assessment_id=job.assessment_id, action='scan_failed', details=f'Scan #{job.id}: stale worker'))
    db.session.commit()
    job_id = db.session.scalar(db.select(ScanJob.id).where(ScanJob.status == 'queued', ScanJob.cancel_requested.is_(False)).order_by(ScanJob.id).limit(1))
    if not job_id:
        return False
    claimed = db.session.execute(db.update(ScanJob).where(ScanJob.id == job_id, ScanJob.status == 'queued', ScanJob.cancel_requested.is_(False)).values(status='running', started_at=now()))
    db.session.commit()
    if not claimed.rowcount:
        return False
    job = db.session.get(ScanJob, job_id)
    job.result = {**(job.result or {}), 'stage': 'Validating the target and collecting its response'}
    db.session.commit()

    def cancelled():
        db.session.refresh(job)
        return job.cancel_requested

    try:
        if not job.assessment.scan_approved or job.target_url != job.assessment.target_url:
            raise ValueError('Target authorization or approval changed. Request approval again.')
        if not job.assessment.owner.enabled:
            raise ValueError('The assessment owner is disabled.')
        profile = (job.result or {}).get('profile', 'passive')
        if profile == 'active':
            from .authorization import active_approval
            if not active_approval(job.assessment):
                raise ValueError('Active scan approval expired or its scope changed. Request approval again.')
        response = fetch(job.target_url, cancelled, time.monotonic() + app.config['SCAN_MAX_SECONDS'])
        records = analyze(response)
        job.pages_checked = 1
        job.result = {'profile': profile, 'stage': 'Running approved active tests with ZAP' if profile == 'active' else 'Analyzing the response with the free ZAP engine'}
        db.session.commit()
        engine = 'Beautiful Soup and built-in passive checks'
        if app.config.get('ZAP_ENABLED'):
            from .zap_engine import analyze_with_zap
            records.extend(analyze_with_zap(app, [response], cancelled, active=profile == 'active'))
            engine = 'ZAP 2.17 + Beautiful Soup + built-in checks'
        from .risk import fingerprint
        unique = {}
        for record in records:
            key = fingerprint(record['title'], record['url'], record.get('method', 'GET'), record.get('parameter', ''), record.get('cwe', ''))
            unique.setdefault(key, record)
        records = list(unique.values())
        if cancelled():
            raise InterruptedError('Scan cancelled.')
        for record in records:
            add_finding(job.assessment, record)
        job.pages_checked = 1
        job.findings_count = len(records)
        job.status = 'completed'
        job.result = {'profile': profile, 'stage': 'Completed', 'engine': engine, 'http_status': response['status'],
                      'final_url': response['url'], 'redirects_followed': len(response['redirects']),
                      'coverage': 'Passive response analysis plus optional approved SQL injection and reflected XSS tests on the target endpoint.' if profile == 'active' else 'Automatic passive analysis of one unauthenticated response. ZAP analyzes a recorded response without replaying requests. No exploit payloads, authenticated testing, or business logic testing.'}
    except InterruptedError:
        db.session.rollback()
        job = db.session.get(ScanJob, job_id)
        job.status = 'cancelled'
        job.error = 'Cancelled by user. No findings saved from this run.'
    except Exception as exc:
        db.session.rollback()
        job = db.session.get(ScanJob, job_id)
        job.status = 'failed'
        # Do not store exception strings containing response data or secrets.
        job.error = str(exc)[:900] if isinstance(exc, (ValueError, TimeoutError)) else f'{type(exc).__name__}: connection or analysis failed. Check target availability and worker logs.'
        app.logger.warning('Automatic scan %s failed (%s)', job_id, type(exc).__name__)
    job.finished_at = now()
    db.session.add(AuditLog(actor_id=job.requested_by_id, assessment_id=job.assessment_id,
                            action=f'scan_{job.status}', details=f'Scan #{job.id}; {job.findings_count} findings'))
    db.session.commit()
    return True
