"""One native HTTPS response, bounded before the existing operator parses it.

No proxy, redirect, cookie, retry, cache or operation executes on import. TLS
uses normal public system roots for the fixed original operator server.
"""
import http.client
import io
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse

SERVER = 'https://yggdrasil.dakasa.me'
CAP = 2 * 1024**2


class Held(Exception):
    pass


def require(ok, guard):
    if not ok:
        raise Held(guard)


class Buffered:
    def __init__(self, status, headers, raw):
        self.status = status
        self.headers = headers
        self.stream = io.BytesIO(raw)

    def read(self, count=-1):
        return self.stream.read(count)

    def close(self):
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def native_open(request, timeout, deadline, facts, *, continuous=None, continuous_deadline=None):
    """Return ONLY after original body EOF/length/Close and socket-watchdog join.

    DNS/connect have their native timeout and the containing original child has
    a separate <=35s hard process owner. No header/body timer grants fresh time.
    After connect, the SAME socket is independently shutdown at the original
    request deadline, including Connection: close bodies where conn.sock=None.
    """
    started = time.monotonic()
    limit = min(deadline, started + min(float(timeout), 35.0))
    require((continuous is None and continuous_deadline is None) or
            (callable(continuous) and continuous_deadline is not None), 'CONTINUOUS_DEADLINE_PAIR')
    def fresh():
        return time.monotonic() < limit and (continuous is None or continuous()[1] < continuous_deadline)
    parsed = urllib.parse.urlsplit(request.full_url)
    require(parsed.scheme == 'https' and parsed.hostname == 'yggdrasil.dakasa.me'
            and parsed.port is None and parsed.username is None
            and parsed.password is None and not parsed.fragment,
            'FIXED_PUBLIC_OPERATOR_HTTPS_ONLY')
    path = parsed.path + ('?' + parsed.query if parsed.query else '')
    headers = dict(request.header_items())
    require(not any(k.lower() in ('cookie', 'proxy-authorization', 'host')
                    for k in headers), 'NO_COOKIE_PROXY_OR_FOREIGN_HOST')
    require(fresh(), 'ORIGINAL_HTTPS_BEFORE_SETUP')
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    remaining = limit - time.monotonic()
    require(remaining > 0, 'ORIGINAL_HTTPS_AFTER_CA_SETUP')
    connection = http.client.HTTPSConnection(parsed.hostname, 443,
                                             timeout=remaining, context=context)
    response = None
    native_socket = None
    stop = threading.Event()
    watcher = None
    raw = None
    entry = {'status': None, 'body_EOF': False, 'declared_length_complete': False,
             'response_closed': False, 'connection_closed': False,
             'same_socket_watchdog_joined': False, 'returned_before_deadline': False}
    facts.append(entry)
    try:
        connection.connect()
        native_socket = connection.sock
        require(native_socket is not None and fresh(),
                'ORIGINAL_TLS_CONNECT_BEFORE_SAME_DEADLINE')

        def expire():
            while not stop.is_set():
                remaining=limit-time.monotonic()
                if continuous is not None:
                    remaining=min(remaining,(continuous_deadline-continuous()[1])/1e9)
                if remaining<=0:
                    try:native_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                    native_socket.close()
                    return
                if stop.wait(min(remaining,.05)):return

        watcher = threading.Thread(target=expire, daemon=True)
        watcher.start()
        remaining = limit - time.monotonic()
        require(remaining > 0, 'ORIGINAL_HTTPS_BEFORE_SEND_DEADLINE')
        native_socket.settimeout(remaining)
        require(fresh(), 'ORIGINAL_HTTPS_AT_SEND_DEADLINE')
        connection.request(request.get_method(), path, body=request.data,
                           headers=headers)
        response = connection.getresponse()
        require(fresh(), 'ORIGINAL_HTTPS_HEADERS_DEADLINE')
        status = response.status
        require(type(status) is int and 100 <= status <= 599,
                'ACTUAL_ORIGINAL_HTTP_STATUS')
        entry['status'] = status
        lengths = response.headers.get_all('Content-Length') or []
        require(len(lengths) <= 1, 'ONE_OR_ABSENT_ORIGINAL_CONTENT_LENGTH')
        if lengths:
            require(lengths[0].isascii() and lengths[0].isdigit()
                    and len(lengths[0]) <= 10, 'CANONICAL_BOUNDED_CONTENT_LENGTH')
            require(not response.headers.get('Transfer-Encoding'),
                    'NO_AMBIGUOUS_LENGTH_AND_TRANSFER_ENCODING')
        expected = response.length
        require(expected is None or type(expected) is int and 0 <= expected <= CAP,
                'BOUNDED_NATIVE_ORIGINAL_RESPONSE_LENGTH')
        raw = response.read(CAP + 1)
        require(len(raw) <= CAP, 'BOUNDED_ORIGINAL_HTTP_BODY')
        require(expected is None or len(raw) == expected,
                'ORIGINAL_DECLARED_CONTENT_LENGTH_COMPLETE')
        require(response.read(1) == b'', 'ORIGINAL_RESPONSE_BODY_EOF')
        entry['body_EOF'] = True
        entry['declared_length_complete'] = True
        headers = response.headers
    finally:
        try:
            if response is not None:
                response.close()
                entry['response_closed'] = True
        finally:
            try:
                connection.close()
                if native_socket is not None:
                    native_socket.close()
                entry['connection_closed'] = True
            finally:
                stop.set()
                if watcher is not None:
                    watcher.join(timeout=max(.001, deadline-time.monotonic()))
                    entry['same_socket_watchdog_joined'] = not watcher.is_alive()
    require(entry['body_EOF'] and entry['declared_length_complete']
            and entry['response_closed'] and entry['connection_closed']
            and entry['same_socket_watchdog_joined']
            and fresh(), 'ORIGINAL_HTTP_COMPLETE_CLOSE_JOIN_DEADLINE')
    entry['returned_before_deadline'] = True
    if status >= 300:
        # The original operator classifies its normal native error in RAM.
        # Body/headers/bearer/CSRF are never part of our public facts.
        raise urllib.error.HTTPError(request.full_url, status, '', headers,
                                     io.BytesIO(raw))
    return Buffered(status, headers, raw)
