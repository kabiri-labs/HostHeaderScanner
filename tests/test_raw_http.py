"""Tests for the raw HTTP response parser and its lightweight response type."""

import unittest

import host_header_scanner as hhs


class RawResponseTests(unittest.TestCase):
    def test_get_is_case_insensitive(self):
        response = hhs.RawResponse(200, [("Content-Type", "text/html")], "")
        self.assertEqual(response.get("content-type"), "text/html")

    def test_get_returns_first_match(self):
        response = hhs.RawResponse(200, [("Host", "a"), ("Host", "b")], "")
        self.assertEqual(response.get("Host"), "a")

    def test_get_missing_returns_none(self):
        response = hhs.RawResponse(200, [], "")
        self.assertIsNone(response.get("Location"))


class RawParseTests(unittest.TestCase):
    def test_empty_input_returns_none(self):
        self.assertIsNone(hhs.RawHTTPClient._parse(b""))

    def test_parses_status_headers_and_body(self):
        raw = (b"HTTP/1.1 302 Found\r\n"
               b"Location: http://evil/\r\n"
               b"X-Test: 1\r\n\r\n"
               b"body-content")
        response = hhs.RawHTTPClient._parse(raw)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.get("Location"), "http://evil/")
        self.assertEqual(response.text, "body-content")

    def test_preserves_duplicate_headers(self):
        raw = b"HTTP/1.1 200 OK\r\nHost: a\r\nHost: b\r\n\r\n"
        response = hhs.RawHTTPClient._parse(raw)
        hosts = [value for name, value in response.headers if name == "Host"]
        self.assertEqual(hosts, ["a", "b"])

    def test_non_numeric_status_becomes_zero(self):
        raw = b"GARBAGE LINE\r\n\r\n"
        response = hhs.RawHTTPClient._parse(raw)
        self.assertEqual(response.status_code, 0)


if __name__ == "__main__":
    unittest.main()
