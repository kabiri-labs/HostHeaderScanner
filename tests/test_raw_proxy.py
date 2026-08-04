"""Tests for CONNECT-tunnel proxy support in the raw HTTP client."""

import base64
import unittest
from unittest import mock

import headerhawk as hhs
from headerhawk.net import raw as hh_raw
from tests.helpers import FakeSession


class FakeSocket:
    """In-memory socket double: records sent bytes, replays queued recv chunks."""

    def __init__(self, recv_chunks=None):
        self.sent = b""
        self._recv = list(recv_chunks or [])
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def settimeout(self, _timeout):
        pass

    def recv(self, _size):
        return self._recv.pop(0) if self._recv else b""

    def close(self):
        self.closed = True


class ParseProxyTests(unittest.TestCase):
    def test_none_returns_none(self):
        self.assertIsNone(hhs.RawHTTPClient._parse_proxy(None))

    def test_host_port_without_scheme(self):
        proxy = hhs.RawHTTPClient._parse_proxy("127.0.0.1:8080")
        self.assertEqual((proxy["host"], proxy["port"]), ("127.0.0.1", 8080))

    def test_scheme_and_default_port(self):
        proxy = hhs.RawHTTPClient._parse_proxy("http://proxy.local")
        self.assertEqual((proxy["host"], proxy["port"]), ("proxy.local", 8080))

    def test_credentials_parsed(self):
        proxy = hhs.RawHTTPClient._parse_proxy("http://user:pass@127.0.0.1:3128")
        self.assertEqual(proxy["username"], "user")
        self.assertEqual(proxy["password"], "pass")
        self.assertEqual(proxy["port"], 3128)

    def test_invalid_returns_none(self):
        self.assertIsNone(hhs.RawHTTPClient._parse_proxy("http://"))


class ReadConnectResponseTests(unittest.TestCase):
    def _client(self):
        return hhs.RawHTTPClient(timeout=1)

    def test_2xx_is_success(self):
        sock = FakeSocket([b"HTTP/1.1 200 Connection established\r\n\r\n"])
        self.assertTrue(self._client()._read_connect_response(sock))

    def test_407_is_failure(self):
        sock = FakeSocket([b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"])
        self.assertFalse(self._client()._read_connect_response(sock))

    def test_closed_connection_is_failure(self):
        sock = FakeSocket([b""])
        self.assertFalse(self._client()._read_connect_response(sock))


class OpenSocketTests(unittest.TestCase):
    def test_direct_connection_without_proxy(self):
        client = hhs.RawHTTPClient(timeout=2)
        sentinel = FakeSocket()
        with mock.patch.object(hh_raw.socket, "create_connection",
                               return_value=sentinel) as conn:
            result = client._open_socket("target.com", 80)
        self.assertIs(result, sentinel)
        conn.assert_called_once_with(("target.com", 80), timeout=2)

    def test_proxy_connection_targets_proxy(self):
        client = hhs.RawHTTPClient(timeout=2, proxy="http://127.0.0.1:8080")
        sock = FakeSocket([b"HTTP/1.1 200 OK\r\n\r\n"])
        with mock.patch.object(hh_raw.socket, "create_connection",
                               return_value=sock) as conn:
            result = client._open_socket("target.com", 443)
        self.assertIs(result, sock)
        conn.assert_called_once_with(("127.0.0.1", 8080), timeout=2)
        self.assertTrue(sock.sent.startswith(b"CONNECT target.com:443 HTTP/1.1"))

    def test_proxy_connect_failure_returns_none_and_closes(self):
        client = hhs.RawHTTPClient(timeout=2, proxy="127.0.0.1:8080")
        sock = FakeSocket([b"HTTP/1.1 502 Bad Gateway\r\n\r\n"])
        with mock.patch.object(hh_raw.socket, "create_connection", return_value=sock):
            self.assertIsNone(client._open_socket("target.com", 443))
        self.assertTrue(sock.closed)


class SendThroughProxyTests(unittest.TestCase):
    def test_http_request_tunnelled_and_parsed(self):
        client = hhs.RawHTTPClient(timeout=1, proxy="http://127.0.0.1:8080")
        sock = FakeSocket([
            b"HTTP/1.1 200 Connection established\r\n\r\n",   # CONNECT reply
            b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nbody",     # tunnelled response
            b"",
        ])
        with mock.patch.object(hh_raw.socket, "create_connection", return_value=sock):
            response = client.send("http", "target.com", 80,
                                   "GET / HTTP/1.1",
                                   ["Host: target.com", "Connection: close"])
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get("X-Test"), "yes")
        # CONNECT precedes the verbatim request line inside the tunnel.
        self.assertTrue(sock.sent.startswith(b"CONNECT target.com:80 HTTP/1.1"))
        self.assertIn(b"GET / HTTP/1.1", sock.sent)

    def test_proxy_authorization_header_sent(self):
        client = hhs.RawHTTPClient(timeout=1, proxy="http://user:pass@127.0.0.1:8080")
        sock = FakeSocket([
            b"HTTP/1.1 200 Connection established\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"",
        ])
        with mock.patch.object(hh_raw.socket, "create_connection", return_value=sock):
            client.send("http", "target.com", 80, "GET / HTTP/1.1",
                        ["Host: target.com"])
        token = base64.b64encode(b"user:pass").decode("ascii")
        self.assertIn(f"Proxy-Authorization: Basic {token}".encode(), sock.sent)


class HostBypassProxyTests(unittest.TestCase):
    def test_proxy_taken_from_session(self):
        session = FakeSession()
        session.proxies = {"http": "http://p:8080", "https": "http://p:8080"}
        test = hhs.HostBypassTest("https://example.com/", "example.com",
                                  session=session, timeout=2)
        self.assertIsNotNone(test.client.proxy)
        self.assertEqual(test.client.proxy["host"], "p")

    def test_no_proxy_when_session_has_none(self):
        test = hhs.HostBypassTest("http://example.com/", "example.com",
                                  session=FakeSession(), timeout=2)
        self.assertIsNone(test.client.proxy)


if __name__ == "__main__":
    unittest.main()
