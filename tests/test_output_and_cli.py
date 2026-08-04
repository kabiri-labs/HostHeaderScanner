"""Tests for report writing, argument parsing and session construction."""

import json
import os
import tempfile
import unittest
from unittest import mock

import headerhawk as hhs
from tests.helpers import FakeSession


class _StubTest:
    """A stand-in test object exposing the attributes ``save_results`` reads."""

    def __init__(self, target_url, vulns, all_results=None):
        self.target_url = target_url
        self.vulnerabilities_found = vulns
        self.all_results = all_results or []


def _finding():
    return {
        "test_type": "Host Header Injection",
        "test_result": "Potentially Vulnerable",
        "url": "http://t/",
        "method": "GET",
        "headers": {"Host": "evil"},
        "payload": "evil",
        "status_code": 200,
        "analysis": "reflected",
        "repro": "curl -s -i 'http://t/'",
    }


class SaveResultsTests(unittest.TestCase):
    def test_no_output_file_is_noop(self):
        # Should simply return without raising.
        self.assertIsNone(hhs.save_results(None, [], verbose=1))

    def test_json_output(self):
        tests = [_StubTest("http://t/", [_finding()])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.json")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                data = json.load(handle)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["payload"], "evil")

    def test_markdown_output(self):
        tests = [_StubTest("http://t/", [_finding()])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.md")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                content = handle.read()
        self.assertIn("# HeaderHawk Report", content)
        self.assertIn("**Total Findings:** 1", content)
        self.assertIn("reflected", content)

    def test_markdown_output_no_findings(self):
        tests = [_StubTest("http://t/", [])]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.md")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                content = handle.read()
        self.assertIn("No vulnerabilities were found.", content)


class ParseArgumentsTests(unittest.TestCase):
    def test_defaults(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.url, "http://t/")
        self.assertEqual(args.threads, 5)
        self.assertEqual(args.verbose, 1)

    def test_thread_bounds_rejected(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--threads", "50"]):
            with self.assertRaises(SystemExit):
                hhs.parse_arguments()

    def test_repeatable_headers(self):
        with mock.patch("sys.argv",
                        ["prog", "http://t/", "-H", "A: 1", "-H", "B: 2"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.headers, ["A: 1", "B: 2"])


class BuildSessionTests(unittest.TestCase):
    def test_sets_user_agent_and_timeout(self):
        session = hhs.build_session(timeout=7, threads=5, insecure=False,
                                    proxy=None, extra_headers=None)
        self.assertIn(hhs.__version__, session.headers["User-Agent"])
        self.assertEqual(session.request_timeout, 7)

    def test_extra_headers_and_proxy_applied(self):
        session = hhs.build_session(timeout=5, threads=5, insecure=True,
                                    proxy="http://127.0.0.1:8080",
                                    extra_headers={"X-Test": "1"})
        self.assertEqual(session.headers["X-Test"], "1")
        self.assertEqual(session.proxies["http"], "http://127.0.0.1:8080")
        self.assertFalse(session.verify)


class HostBypassConstructionTests(unittest.TestCase):
    def test_insecure_mirrors_session_verify(self):
        secure = hhs.HostBypassTest("https://example.com/p?q=1", "example.com",
                                    session=FakeSession(verify=True), timeout=3)
        self.assertEqual(secure.connect_port, 443)
        self.assertEqual(secure.path, "/p?q=1")
        self.assertTrue(secure.client.verify)

        insecure = hhs.HostBypassTest("http://example.com/", "example.com",
                                      session=FakeSession(verify=False), timeout=3)
        self.assertEqual(insecure.connect_port, 80)
        self.assertFalse(insecure.client.verify)

    def test_techniques_carry_marker(self):
        test = hhs.HostBypassTest("http://example.com/", "example.com",
                                  session=FakeSession(), timeout=3)
        techniques = test.techniques("MARKER.example-collab.com")
        names = [name for name, _, _ in techniques]
        self.assertIn("Duplicate Host header", names)
        self.assertIn("Absolute-URI request line", names)
        # Every technique must reference the marker somewhere.
        for _, request_line, headers in techniques:
            self.assertTrue("MARKER" in request_line or any("MARKER" in h for h in headers))


if __name__ == "__main__":
    unittest.main()
