"""A minimal raw HTTP/1.1 client used by the wire-level checks."""

import base64
import socket
import ssl
import time
from collections import namedtuple
from urllib.parse import urlparse

# A raw reply plus how long it took and whether the peer simply never answered.
# The elapsed time is what a timing-based desync probe reads; timed_out
# distinguishes "still holding the request open" from "answered slowly".
TimedResponse = namedtuple("TimedResponse", "response elapsed timed_out")

class RawResponse:
    """Lightweight response object produced by the raw HTTP client."""

    def __init__(self, status_code, headers, text):
        self.status_code = status_code
        self.headers = headers  # list of (name, value) preserving duplicates
        self.text = text

    def get(self, name):
        name = name.lower()
        for header, value in self.headers:
            if header.lower() == name:
                return value
        return None


class RawHTTPClient:
    """Minimal raw HTTP/1.1 client.

    Unlike ``requests``, it sends the request line and header lines verbatim,
    which is what makes duplicate ``Host`` headers, absolute-URI request lines
    and obsolete line folding possible - the building blocks of most Host
    header validation bypasses.
    """

    def __init__(self, timeout=10, verify=True, max_bytes=200_000, proxy=None,
                 rate_limiter=None):
        self.timeout = timeout
        self.verify = verify
        self.max_bytes = max_bytes
        self.proxy = self._parse_proxy(proxy)
        self.rate_limiter = rate_limiter

    @staticmethod
    def _parse_proxy(proxy):
        """Parse an HTTP proxy URL into its parts, or return None."""
        if not proxy:
            return None
        parsed = urlparse(proxy if "://" in proxy else f"http://{proxy}")
        if not parsed.hostname:
            return None
        return {
            "host": parsed.hostname,
            "port": parsed.port or 8080,
            "username": parsed.username,
            "password": parsed.password,
        }

    def _open_socket(self, host, port):
        """Open a raw TCP socket to host:port, tunnelling via CONNECT if a proxy
        is configured.

        Tunnelling (rather than absolute-URI forwarding) is essential: it keeps
        the malformed request line and duplicate headers intact end-to-end, so
        the bypass techniques survive the trip through an intercepting proxy such
        as Burp.
        """
        if not self.proxy:
            return socket.create_connection((host, port), timeout=self.timeout)
        sock = socket.create_connection((self.proxy["host"], self.proxy["port"]),
                                        timeout=self.timeout)
        lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
        if self.proxy["username"] is not None:
            token = base64.b64encode(
                f"{self.proxy['username']}:{self.proxy['password'] or ''}"
                .encode("latin-1", "ignore")).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        lines.append("Connection: keep-alive")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "ignore"))
        if not self._read_connect_response(sock):
            sock.close()
            return None
        return sock

    def _read_connect_response(self, sock):
        """Read the proxy's reply to CONNECT; return True on a 2xx tunnel."""
        sock.settimeout(self.timeout)
        buffer = b""
        while b"\r\n\r\n" not in buffer and len(buffer) < 8192:
            try:
                chunk = sock.recv(1024)
            except (socket.timeout, OSError):
                return False
            if not chunk:
                return False
            buffer += chunk
        status_line = buffer.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split(" ", 2)
        return len(parts) > 1 and parts[1].startswith("2")

    def send(self, scheme, host, port, request_line, header_lines, sni_host=None):
        request = request_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n"
        timed = self.send_raw(scheme, host, port, request, sni_host=sni_host)
        return timed.response

    def send_raw(self, scheme, host, port, request, sni_host=None,
                 read_timeout=None):
        """Send a request byte-for-byte and time how long the reply takes.

        Nothing is appended to ``request``: a body that deliberately disagrees
        with its own Content-Length is the whole point of the desync probes, so
        the caller owns every byte. Returns a ``TimedResponse`` whose
        ``timed_out`` says whether the peer went quiet rather than answering,
        which is the signal a timing-based desync test is looking for.
        """
        if self.rate_limiter is not None:
            self.rate_limiter.acquire()
        timeout = self.timeout if read_timeout is None else read_timeout
        raw = b""
        sock = None
        timed_out = False
        started = time.monotonic()
        try:
            sock = self._open_socket(host, port)
            if sock is None:
                return TimedResponse(None, time.monotonic() - started, False)
            if scheme == "https":
                context = ssl.create_default_context()
                if not self.verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=sni_host or host)
            sock.sendall(request.encode("latin-1", "ignore"))
            sock.settimeout(timeout)
            while len(raw) < self.max_bytes:
                try:
                    chunk = sock.recv(8192)
                except (socket.timeout, ssl.SSLError):
                    # No reply within the budget. With nothing received at all
                    # the peer is still holding the request open, which is the
                    # delay a desync probe provokes; a partial reply just means
                    # the response ended without the connection closing.
                    timed_out = not raw
                    break
                if not chunk:
                    break
                raw += chunk
        except OSError:
            return TimedResponse(None, time.monotonic() - started, False)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return TimedResponse(self._parse(raw), time.monotonic() - started,
                             timed_out)

    @staticmethod
    def _parse(raw):
        if not raw:
            return None
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status_line = lines[0].decode("latin-1", "replace") if lines else ""
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers = []
        for line in lines[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers.append((
                    name.decode("latin-1", "replace").strip(),
                    value.decode("latin-1", "replace").strip(),
                ))
        return RawResponse(status, headers, body.decode("latin-1", "replace"))
