"""Loopback upstream proxy for explicitly approved active ZAP tests.

Every new target connection is restricted to the approved origin and pinned to
a validated public IP, including CONNECT tunnels. No environment proxy is used.
Only ZAP's selected SQLi/XSS rules use this gateway, for a short bounded run.
"""
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

from .scanner import PinnedHTTPConnection, origin, validated_target


class ScanGateway:
    def __init__(self, target, seconds=95):
        self.target = target
        self.deadline = time.monotonic() + seconds
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.connections = 0
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def log_message(self, *args):
                pass

            def permitted(self, url):
                if gateway.stop.is_set() or time.monotonic() >= gateway.deadline:
                    raise ValueError('Active scan window ended.')
                if origin(url) != origin(gateway.target):
                    raise ValueError('Destination is outside the approved origin.')
                with gateway.lock:
                    gateway.connections += 1
                    if gateway.connections > 150:
                        raise ValueError('Active scan connection limit reached.')
                return validated_target(url)

            def do_CONNECT(self):
                upstream = None
                try:
                    if '/' in self.path or '@' in self.path:
                        raise ValueError('Invalid CONNECT authority.')
                    parsed, host, port, ips = self.permitted('https://' + self.path)
                    upstream = socket.create_connection((ips[0], port), timeout=8)
                    self.send_response(200, 'Connection established')
                    self.end_headers()
                    self.connection.setblocking(False)
                    upstream.setblocking(False)
                    total = 0
                    while not gateway.stop.is_set() and time.monotonic() < gateway.deadline:
                        ready, _, _ = select.select([self.connection, upstream], [], [], .25)
                        for source in ready:
                            data = source.recv(16384)
                            if not data:
                                return
                            total += len(data)
                            if total > 8 * 1024 * 1024:
                                return
                            destination = upstream if source is self.connection else self.connection
                            destination.settimeout(5)
                            destination.sendall(data)
                            destination.setblocking(False)
                except (ValueError, OSError):
                    if upstream is None:
                        self.send_error(403, 'Target blocked by scan scope policy')
                finally:
                    if upstream:
                        upstream.close()

            def forward(self):
                connection = None
                try:
                    parsed, host, port, ips = self.permitted(self.path)
                    # For plain HTTP, also enforce the exact approved endpoint.
                    if (parsed.path or '/') != (urlsplit(gateway.target).path or '/'):
                        raise ValueError('Endpoint is outside the approved path.')
                    if self.headers.get('Transfer-Encoding'):
                        raise ValueError('Chunked uploads are not supported.')
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 <= length <= 128 * 1024:
                        raise ValueError('Request body exceeds scan limits.')
                    body = self.rfile.read(length) if length else None
                    headers = {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection', 'proxy-connection', 'proxy-authorization', 'authorization', 'cookie', 'transfer-encoding')}
                    headers['Connection'] = 'close'
                    connection = PinnedHTTPConnection(host, port, ips[0], parsed.scheme == 'https', 8)
                    connection.request(self.command, urlunsplit(('', '', parsed.path or '/', parsed.query, '')), body=body, headers=headers)
                    response = connection.getresponse()
                    data = response.read(1024 * 1024 + 1)
                    if len(data) > 1024 * 1024:
                        raise ValueError('Response exceeds scan limits.')
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                            self.send_header(key, value)
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (ValueError, OSError):
                    self.send_error(403, 'Target blocked or unreachable')
                finally:
                    if connection:
                        connection.close()

            do_GET = forward
            do_POST = forward

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .2}, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
