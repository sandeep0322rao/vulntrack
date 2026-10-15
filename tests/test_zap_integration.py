"""Opt-in integration against a local disposable vulnerable fixture only.

Run with ZAP_INTEGRATION=1. The sole network override is confined to this test:
the fake .example origin maps to its own ephemeral loopback HTTP server. The
production gateway continues rejecting every private/internal destination.
"""
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('ZAP_INTEGRATION') != '1', reason='Set ZAP_INTEGRATION=1 for the local scanner integration test.')


def test_real_zap_active_rules_on_local_fixture(app, monkeypatch):
    from vulntrack.services import scan_gateway
    from vulntrack.services.zap_engine import analyze_with_zap

    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            value = parse_qs(urlsplit(self.path).query).get('q', [''])[0]
            error = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near query' if "'" in value else ''
            body = f'<html><head><title>Disposable local test</title></head><body>Search result: {value}<p>{error}</p></body></html>'.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def fixture_only_target(url):
        parsed = urlsplit(url)
        if parsed.scheme != 'http' or parsed.hostname != 'zap-fixture.example':
            raise ValueError('Only this disposable fixture is allowed.')
        return parsed, 'zap-fixture.example', server.server_address[1], ['127.0.0.1']
    monkeypatch.setattr(scan_gateway, 'validated_target', fixture_only_target)
    response = {'url': 'http://zap-fixture.example/echo?q=hello', 'status': 200,
                'headers': [('Content-Type', 'text/html; charset=utf-8')],
                'body': b'<html><head><title>Disposable local test</title></head><body>Search result: hello<p></p></body></html>'}
    try:
        records = analyze_with_zap(app, [response], active=True)
        titles = '\n'.join(record['title'] for record in records)
        print('Real ZAP local fixture detections:\n' + titles)
        assert 'SQL Injection' in titles
        assert 'Cross Site Scripting' in titles
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
