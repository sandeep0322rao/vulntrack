import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..constants import SEVERITIES


def score(severity, exploitability, business_impact, exposure):
    values = [exploitability, business_impact, exposure]
    if severity not in SEVERITIES or any(not isinstance(v, int) or not 0 <= v <= 100 for v in values):
        raise ValueError('Risk inputs must be integers from 0 to 100 and severity must be valid.')
    return round(SEVERITIES[severity] * .40 + exploitability * .25 + business_impact * .25 + exposure * .10, 2)


def priority(value):
    return 'Critical' if value >= 80 else 'High' if value >= 60 else 'Medium' if value >= 40 else 'Low'


def normalize_url(value):
    u = urlsplit(value.strip())
    host = (u.hostname or '').lower().encode('idna').decode('ascii')
    if ':' in host:
        host = f'[{host}]'
    port = u.port
    if port and not ((u.scheme.lower() == 'https' and port == 443) or (u.scheme.lower() == 'http' and port == 80)):
        host += f':{port}'
    # Paths are case-sensitive, and a trailing slash can identify a different resource.
    return urlunsplit((u.scheme.lower(), host, u.path or '/', urlencode(sorted(parse_qsl(u.query, keep_blank_values=True))), ''))


def fingerprint(title, url, method='GET', parameter='', cwe=''):
    parts = [re.sub(r'\s+', ' ', title.strip().lower()), normalize_url(url), method.upper(), parameter.strip(), cwe.strip().upper()]
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()


def suggest_category(title, cwe='', description=''):
    cwe_id = str(cwe).upper().replace('CWE-', '').strip()
    groups = {
        'A01:2025': {'22', '284', '285', '352', '639', '862', '863', '918'},
        'A02:2025': {'16', '200', '209', '548', '614', '693', '1004'},
        'A04:2025': {'295', '319', '326', '327'},
        'A05:2025': {'78', '79', '89', '90', '94'},
        'A07:2025': {'287', '307', '384', '521', '613'},
        'A08:2025': {'345', '502'},
        'A09:2025': {'117', '778'},
        'A10:2025': {'248', '390', '755'},
    }
    for category, identifiers in groups.items():
        if cwe_id in identifiers:
            return category, f'Suggested from CWE-{cwe_id}; assessor review required.'
    text = f'{title} {description}'.lower()
    rules = [
        ('A05:2025', r'sql injection|cross.site scripting|\bxss\b|command injection'),
        ('A01:2025', r'access control|\bidor\b|\bcsrf\b|\bssrf\b|cors'),
        ('A03:2025', r'vulnerable dependenc|outdated librar|supply chain'),
        ('A04:2025', r'\btls\b|\bssl\b|cleartext|plaintext|mixed content|unencrypted'),
        ('A07:2025', r'authentication|password|session fixation|brute.force'),
        ('A08:2025', r'deserializ|integrity'),
        ('A09:2025', r'logging|monitoring|alerting'),
        ('A10:2025', r'exception handling|unhandled exception'),
        ('A02:2025', r'header|cookie|misconfigur|information disclosure'),
        ('A06:2025', r'insecure design|business logic'),
    ]
    for category, pattern in rules:
        if re.search(pattern, text):
            return category, 'Suggested by keyword rules; assessor review required.'
    return 'Unmapped', 'No reliable heuristic match. Classify manually.'
