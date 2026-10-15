"""Run official free ZAP rules in a fresh private session for each job.

Passive mode imports recorded responses without replaying them. Explicitly
approved active mode uses only SQLi/XSS rules through the pinned-origin gateway.
Every job receives a new loopback API key and shuts down its scanner process.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import re
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from urllib.parse import urlsplit

from .intake import clean


def installation(app):
    jar = Path(app.config['ZAP_JAR'])
    java = app.config.get('JAVA_BIN') or shutil.which('java')
    return jar if jar.is_file() else None, java


def available(app):
    jar, java = installation(app)
    return bool(jar and java)


def recorded_har(responses):
    entries = []
    for response in responses:
        # Credentials and cookie values are unnecessary for the offline rules.
        headers = []
        for name, value in response['headers']:
            if name.lower() == 'set-cookie':
                first, *attrs = value.split(';')
                cookie_name = first.split('=', 1)[0]
                value = cookie_name + '=REDACTED' + ''.join(';' + attr for attr in attrs)
            if name.lower() not in ('authorization', 'proxy-authorization'):
                headers.append({'name': name, 'value': value})
        entries.append({
            'startedDateTime': datetime.now(timezone.utc).isoformat(timespec='milliseconds'), 'time': 0,
            'request': {'method': 'GET', 'url': response['url'], 'httpVersion': 'HTTP/1.1',
                        'headers': [{'name': 'Host', 'value': urlsplit(response['url']).netloc}, {'name': 'User-Agent', 'value': 'VulnTrack-Authorized-Scan/1.0'}], 'queryString': [], 'cookies': [], 'headersSize': -1, 'bodySize': 0},
            'response': {'status': response['status'], 'statusText': 'OK', 'httpVersion': 'HTTP/1.1',
                         'headers': headers, 'cookies': [], 'redirectURL': '', 'headersSize': -1,
                         'bodySize': len(response['body']), 'content': {'size': len(response['body']),
                         'mimeType': next((v for k, v in response['headers'] if k.lower() == 'content-type'), 'text/html'),
                         'text': base64.b64encode(response['body']).decode('ascii'), 'encoding': 'base64'}},
            'cache': {}, 'timings': {'send': 0, 'wait': 0, 'receive': 0},
        })
    return {'log': {'version': '1.2', 'creator': {'name': 'VulnTrack', 'version': '1'}, 'entries': entries}}


def analyze_with_zap(app, responses, cancelled=lambda: False, active=False):
    jar, java = installation(app)
    if not jar or not java:
        raise ValueError('The free ZAP engine is not installed. Run install-zap.ps1 and install Java 17+ on this machine.')
    work_root = Path(app.instance_path).resolve() / 'zap-work'
    work_root.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix='scan-', dir=work_root)
    work = Path(temporary.name).resolve()
    assert work.is_relative_to(work_root.resolve())
    process = None
    log = None
    gateway = None
    try:
        if active:
            from .scan_gateway import ScanGateway
            gateway = ScanGateway(responses[0]['url']).start()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        api_key = secrets.token_urlsafe(32)
        har = work / 'responses.har'
        har.write_text(json.dumps(recorded_har(responses)), encoding='utf-8')
        # Dedicated session, no update checks, no telemetry. HTTP egress is sent
        # to a closed loopback port as an extra guard for offline analysis.
        config = work / 'scanner.properties'
        config.write_text('\n'.join([
            'api.key=' + api_key, 'api.disablekey=false', 'api.addrs.addr.name=127.0.0.1',
            'api.addrs.addr.regex=false', 'start.checkForUpdates=false', 'start.checkAddonUpdates=false',
            'autoupdate.checkOnStart=false', 'stats.enabled=false',
            'network.connection.httpProxy.enabled=true', 'network.connection.httpProxy.host=127.0.0.1',
            'network.connection.httpProxy.port=' + str(gateway.port if gateway else 9), 'network.connection.timeoutInSecs=5',
        ]), encoding='utf-8')
        log = (work / 'engine.log').open('w', encoding='utf-8')
        command = [str(java), '-Xmx512m', '-Djava.awt.headless=true', '-jar', str(jar.resolve()),
                   '-daemon', '-silent', '-host', '127.0.0.1', '-port', str(port), '-dir', str(work / 'session'), '-configfile', str(config)]
        process = subprocess.Popen(command, cwd=jar.parent, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + app.config.get('ZAP_MAX_SECONDS', 120) + (100 if active else 0)

        def api(component, kind, action, **parameters):
            request = Request(f'http://127.0.0.1:{port}/JSON/{component}/{kind}/{action}/',
                              data=urlencode({'apikey': api_key, **parameters}).encode(), method='POST')
            try:
                with opener.open(request, timeout=5) as response:
                    data = json.load(response)
            except HTTPError as exc:
                if app.testing:
                    log.flush()
                    diagnostics = (work / 'engine.log').read_text(encoding='utf-8', errors='replace')[-6000:].replace(api_key, '[REDACTED]')
                    app.logger.warning('ZAP test diagnostics: %s; API error: %s', diagnostics, exc.read(1500).decode(errors='replace').replace(api_key, '[REDACTED]'))
                raise ValueError(f'ZAP rejected the {component}/{action} operation (HTTP {exc.code}). Check scanner compatibility.') from None
            if 'code' in data:
                raise ValueError('ZAP could not process the captured responses. Check the local scanner installation.')
            return data

        def check_state():
            if cancelled():
                raise InterruptedError('Scan cancelled.')
            if time.monotonic() >= deadline:
                raise TimeoutError('ZAP analysis reached its time limit. No partial findings were saved.')
            if process.poll() is not None:
                raise ValueError('ZAP stopped before analysis completed. Check Java 17+ and the scanner installation.')

        while True:
            check_state()
            try:
                api('core', 'view', 'version')
                break
            except (URLError, ConnectionError, TimeoutError, OSError):
                time.sleep(.4)
        api('core', 'action', 'setMode', mode='safe')
        if active:
            # Only these two low-strength rules are enabled; no crawling,
            # OAST callbacks, file upload probes, or arbitrary scan policies.
            from urllib.parse import urlsplit, urlunsplit
            target = responses[0]['url']
            parsed = urlsplit(target)
            endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', '', ''))
            context = api('context', 'action', 'newContext', contextName='approved-target')['contextId']
            api('context', 'action', 'includeInContext', contextName='approved-target', regex=re.escape(endpoint) + r'(?:\?[^#]*)?')
            api('context', 'action', 'setContextInScope', contextName='approved-target', booleanInScope='true')
            api('core', 'action', 'setMode', mode='protect')
        api('exim', 'action', 'importHar', filePath=str(har), sendRequests='false', maxMessages=len(responses))
        if active:
            if app.testing:
                app.logger.warning('ZAP fixture context: %s; URLs: %s', api('context', 'view', 'context', contextName='approved-target'), api('context', 'view', 'urls', contextName='approved-target'))
            api('ascan', 'action', 'disableAllScanners')
            api('ascan', 'action', 'enableScanners', ids='40012,40018')
            for rule in ('40012', '40018'):
                api('ascan', 'action', 'setScannerAttackStrength', id=rule, attackStrength='LOW')
                api('ascan', 'action', 'setScannerAlertThreshold', id=rule, alertThreshold='MEDIUM')
            api('ascan', 'action', 'setOptionMaxScanDurationInMins', Integer=1)
            api('ascan', 'action', 'setOptionMaxRuleDurationInMins', Integer=1)
            api('ascan', 'action', 'setOptionThreadPerHost', Integer=1)
            api('ascan', 'action', 'setOptionDelayInMs', Integer=250)
            gateway.deadline = time.monotonic() + 90
            scan_id = api('ascan', 'action', 'scan', url=target, recurse='false', inScopeOnly='true', contextId=context)['scan']
            while int(api('ascan', 'view', 'status', scanId=scan_id)['status']) < 100:
                check_state()
                time.sleep(.5)
        while True:
            check_state()
            if int(api('pscan', 'view', 'recordsToScan')['recordsToScan']) == 0:
                break
            time.sleep(.3)
        alerts = api('core', 'view', 'alerts', start=0, count=2000).get('alerts', [])
        allowed_urls = {r['url'] for r in responses}
        records = []
        for alert in alerts:
            if not active and alert.get('url') not in allowed_urls:
                continue
            if active:
                from .scanner import origin
                if origin(alert.get('url', '')) != origin(responses[0]['url']):
                    continue
            records.append({
                'title': clean(alert.get('alert') or alert.get('name'), 240), 'url': alert['url'], 'method': 'GET',
                'parameter': clean(alert.get('param'), 160), 'cwe': clean(alert.get('cweid'), 40),
                'severity': alert.get('risk') if alert.get('risk') in ('High', 'Medium', 'Low', 'Informational') else 'Informational',
                'confidence': alert.get('confidence') if alert.get('confidence') in ('Low', 'Medium', 'High', 'Confirmed') else 'Needs review',
                'description': clean(alert.get('description')), 'evidence': 'Cookie attribute observation. Cookie values omitted.' if 'cookie' in str(alert.get('alert', '')).lower() else clean(alert.get('evidence')),
                'remediation': clean(alert.get('solution')), 'source': 'ZAP active scan' if active else 'ZAP automatic scan',
            })
        return records
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if log:
            log.close()
        if gateway:
            gateway.close()
        temporary.cleanup()
