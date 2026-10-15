import json
import re

from bs4 import BeautifulSoup
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

from ..extensions import db
from ..models import Finding
from .risk import fingerprint, score, suggest_category

MAX_FINDINGS = 2000
MAX_TEXT = 12000


def clean(value, limit=MAX_TEXT):
    text = BeautifulSoup(str(value or '')[:limit * 3], 'html.parser').get_text(' ', strip=True)
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)[:limit]


def zap_records(payload, extension):
    """Parse and validate the entire upload before any rows are inserted."""
    records = []

    def append(alert, instance, base):
        risk = str(alert.get('riskcode', '0'))
        severity = {'0': 'Informational', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical'}.get(risk)
        if severity is None:
            raise ValueError('A ZAP alert contains an invalid riskcode.')
        url = str(instance.get('uri') or alert.get('uri') or base).strip()
        from ..forms import valid_http_url
        valid_http_url(url)
        records.append({
            'title': clean(alert.get('alert') or alert.get('name') or 'Untitled ZAP alert', 240),
            'url': url, 'method': clean(instance.get('method') or 'GET', 10).upper(),
            'parameter': clean(instance.get('param'), 160),
            'cwe': clean(alert.get('cweid'), 40), 'severity': severity,
            'confidence': {'0': 'False positive', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Confirmed'}.get(str(alert.get('confidence', '1')), 'Needs review'),
            'description': clean(alert.get('desc')), 'evidence': clean(instance.get('evidence') or alert.get('otherinfo')),
            'remediation': clean(alert.get('solution')), 'source': 'ZAP import',
        })
        if len(records) > MAX_FINDINGS:
            raise ValueError(f'Import is limited to {MAX_FINDINGS} finding instances per file.')

    try:
        if extension == 'json':
            document = json.loads(payload)
            if not isinstance(document, dict) or 'site' not in document:
                raise ValueError('Expected a ZAP JSON report with a site array.')
            sites = document['site']
            if isinstance(sites, dict):
                sites = [sites]
            if not isinstance(sites, list):
                raise ValueError('Invalid ZAP site list.')
            for site in sites:
                if not isinstance(site, dict):
                    raise ValueError('Invalid ZAP site.')
                for alert in site.get('alerts', []):
                    instances = alert.get('instances') or [{}]
                    if not isinstance(instances, list):
                        raise ValueError('Invalid ZAP instances.')
                    for instance in instances:
                        append(alert, instance, site.get('@name', ''))
        elif extension == 'xml':
            root = ElementTree.fromstring(payload)
            if root.tag != 'OWASPZAPReport':
                raise ValueError('Expected an OWASPZAPReport XML root.')
            for site in root.findall('site'):
                for node in site.findall('./alerts/alertitem'):
                    alert = {child.tag: child.text or '' for child in node if child.tag != 'instances'}
                    for inst in node.findall('./instances/instance') or [None]:
                        instance = {c.tag: c.text or '' for c in inst} if inst is not None else {}
                        append(alert, instance, site.get('name', ''))
        else:
            raise ValueError('Only ZAP .json and .xml exports are supported.')
    except (DefusedXmlException, ParseError) as exc:
        raise ValueError('Unsafe or malformed XML was rejected.') from exc
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
        raise ValueError('Malformed or unsupported ZAP export. Check report structure and URL fields.') from exc
    if not records:
        raise ValueError('No alert instances found in this report.')
    return records


def add_finding(assessment, data):
    data = dict(data)
    category, reason = suggest_category(data['title'], data.get('cwe', ''), data.get('description', ''))
    data.setdefault('category', category)
    data.setdefault('mapping_reason', reason)
    for field, default in [('exploitability', 50), ('business_impact', 50), ('exposure', 75)]:
        data.setdefault(field, default)
    fp = fingerprint(data['title'], data['url'], data.get('method', 'GET'), data.get('parameter', ''), data.get('cwe', ''))
    duplicate = db.session.scalar(db.select(Finding).where(Finding.assessment_id == assessment.id, Finding.fingerprint == fp).order_by(Finding.id))
    finding = Finding(assessment_id=assessment.id, fingerprint=fp, duplicate_of_id=duplicate.id if duplicate else None, **data)
    finding.risk_score = score(finding.severity, data['exploitability'], data['business_impact'], data['exposure'])
    db.session.add(finding)
    db.session.flush()
    return finding
