import http.client
import socket
import threading
from urllib.parse import urlsplit

from vulntrack.services import scan_gateway


def test_gateway_blocks_other_origins_and_private_destinations(monkeypatch):
    gateway = scan_gateway.ScanGateway('http://approved.example/').start()
    calls = []
    def forbidden_private(url):
        calls.append(url)
        raise ValueError('Private destination rejected')
    monkeypatch.setattr(scan_gateway, 'validated_target', forbidden_private)
    try:
        for target in ['http://other.example/', 'http://169.254.169.254/latest/meta-data', 'http://approved.example/']:
            connection = http.client.HTTPConnection('127.0.0.1', gateway.port, timeout=3)
            connection.request('GET', target)
            assert connection.getresponse().status == 403
            connection.close()
        assert calls == ['http://approved.example/']
    finally:
        gateway.close()


def test_connect_tunnel_is_pinned_and_rejects_other_hosts(monkeypatch):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    observed = []
    def echo():
        connection, _ = listener.accept()
        with connection:
            observed.append(connection.recv(100))
            connection.sendall(b'fixture-reply')
    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    def fixture_destination(url):
        return urlsplit(url), 'approved.example', listener.getsockname()[1], ['127.0.0.1']
    monkeypatch.setattr(scan_gateway, 'validated_target', fixture_destination)
    gateway = scan_gateway.ScanGateway('https://approved.example/').start()
    try:
        denied = http.client.HTTPConnection('127.0.0.1', gateway.port, timeout=3)
        denied.request('CONNECT', 'private.example:443')
        assert denied.getresponse().status == 403
        denied.close()
        client = socket.create_connection(('127.0.0.1', gateway.port), timeout=3)
        with client:
            client.sendall(b'CONNECT approved.example:443 HTTP/1.0\r\n\r\n')
            header = bytearray()
            while not header.endswith(b'\r\n\r\n'):
                header.extend(client.recv(1))
            assert b'200 Connection established' in header
            client.sendall(b'fixture-request')
            assert client.recv(100) == b'fixture-reply'
        thread.join(timeout=2)
        assert observed == [b'fixture-request']
    finally:
        gateway.close()
        listener.close()
