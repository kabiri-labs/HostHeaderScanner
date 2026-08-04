"""Tests for TLS verification handling and how a certificate failure is reported.

A scanner is routinely pointed at staging and lab hosts with self-signed
certificates, so --insecure has to actually disable verification - and when it
was not passed, the run must say that certificates were the problem rather than
leaving the target looking unreachable.
"""

import io
import unittest
from unittest import mock

import requests

import headerhawk as hhs
from headerhawk.core import output as hh_output
from headerhawk.core.session import _Session
from tests.helpers import FakeResponse, FakeSession


class VerifyIsNotOverriddenByTheEnvironmentTests(unittest.TestCase):
    """requests reads REQUESTS_CA_BUNDLE whenever a request omits `verify`.

    The bundle it finds there beats session.verify, so on a CI runner or a
    corporate image that sets one, --insecure was silently ignored.
    """

    def _captured_kwargs(self, verify):
        session = _Session()
        session.verify = verify
        with mock.patch.object(requests.Session, "request") as parent:
            session.request("GET", "https://example.com/")
        return parent.call_args.kwargs

    def test_insecure_session_names_verify_explicitly(self):
        # Naming it stops merge_environment_settings consulting the environment.
        self.assertIs(self._captured_kwargs(False)["verify"], False)

    def test_verifying_session_leaves_verify_alone(self):
        # A target that legitimately needs a custom CA bundle from the
        # environment must still get one, so this must not be forced.
        self.assertNotIn("verify", self._captured_kwargs(True))

    def test_a_caller_supplied_verify_still_wins(self):
        session = _Session()
        session.verify = False
        with mock.patch.object(requests.Session, "request") as parent:
            session.request("GET", "https://example.com/", verify="/ca.pem")
        self.assertEqual(parent.call_args.kwargs["verify"], "/ca.pem")

    def test_build_session_marks_an_insecure_session(self):
        session = hhs.build_session(timeout=1, threads=1, insecure=True,
                                    proxy=None, extra_headers=None)
        self.assertIs(session.verify, False)

    def test_build_session_leaves_verification_on_by_default(self):
        session = hhs.build_session(timeout=1, threads=1, insecure=False,
                                    proxy=None, extra_headers=None)
        self.assertIsNot(session.verify, False)


class TlsFailureAccountingTests(unittest.TestCase):
    def test_certificate_failures_are_counted_separately(self):
        stats = hhs.RequestStats()
        stats.record(False, tls_error=True)
        stats.record(False, tls_error=True)
        self.assertEqual(stats.failed, 2)
        self.assertEqual(stats.tls_failed, 2)
        self.assertTrue(stats.all_tls_failures)

    def test_mixed_failures_are_not_all_tls(self):
        stats = hhs.RequestStats()
        stats.record(False, tls_error=True)
        stats.record(False)
        self.assertFalse(stats.all_tls_failures)

    def test_no_failures_means_no_tls_verdict(self):
        stats = hhs.RequestStats()
        stats.record(True)
        self.assertFalse(stats.all_tls_failures)

    def test_a_check_reports_an_ssl_error_as_a_tls_failure(self):
        session = FakeSession(responses=[requests.exceptions.SSLError("bad cert")])
        stats = hhs.RequestStats()
        test = hhs.HostInjectionTest("https://t/", "t", session=session,
                                     timeout=1, quiet=True, stats=stats)
        self.assertIsNone(test.request("GET"))
        self.assertEqual(stats.tls_failed, 1)

    def test_an_ordinary_failure_is_not_a_tls_failure(self):
        session = FakeSession(responses=[requests.ConnectionError("refused")])
        stats = hhs.RequestStats()
        test = hhs.HostInjectionTest("https://t/", "t", session=session,
                                     timeout=1, quiet=True, stats=stats)
        test.request("GET")
        self.assertEqual(stats.tls_failed, 0)
        self.assertEqual(stats.failed, 1)


class _Stub:
    def __init__(self, url="https://t/"):
        self.target_url = url
        self.test_type = "Host Header Injection"
        self.vulnerabilities_found = []
        self.all_results = []


class SummaryHintTests(unittest.TestCase):
    def _summary(self, stats):
        buffer = io.StringIO()
        with mock.patch.object(hh_output, "_QUIET", False):
            with mock.patch("sys.stdout", buffer):
                hhs.print_summary([_Stub()], ["https://t/"], stats)
        return buffer.getvalue()

    def test_certificate_failures_suggest_insecure(self):
        stats = hhs.RequestStats()
        for _ in range(3):
            stats.record(False, tls_error=True)
        output = self._summary(stats)
        self.assertIn("TLS certificate error", output)
        self.assertIn("--insecure", output)

    def test_ordinary_failures_do_not_suggest_insecure(self):
        # An unreachable host is a different problem; pointing at --insecure
        # would send the reader down the wrong path.
        stats = hhs.RequestStats()
        for _ in range(3):
            stats.record(False)
        output = self._summary(stats)
        self.assertIn("appear unreachable", output)
        self.assertNotIn("--insecure", output)

    def test_a_successful_scan_says_nothing_about_certificates(self):
        stats = hhs.RequestStats()
        stats.record(True)
        self.assertNotIn("--insecure", self._summary(stats))


class RawClientTlsTests(unittest.TestCase):
    def test_insecure_session_yields_a_non_verifying_raw_client(self):
        # The wire-level checks build their own TLS context rather than going
        # through requests, so they need the same setting carried across.
        session = FakeSession(verify=False)
        for cls in (hhs.HostBypassTest, hhs.RequestSmugglingTest):
            test = cls("https://example.com/", "example.com", session=session,
                       timeout=1, quiet=True)
            self.assertIs(test.client.verify, False, cls.__name__)

    def test_verifying_session_yields_a_verifying_raw_client(self):
        session = FakeSession(verify=True)
        for cls in (hhs.HostBypassTest, hhs.RequestSmugglingTest):
            test = cls("https://example.com/", "example.com", session=session,
                       timeout=1, quiet=True)
            self.assertIs(test.client.verify, True, cls.__name__)


class PostureOverTlsTests(unittest.TestCase):
    def test_https_target_is_assessed_normally(self):
        # Sanity that nothing about the https path changes what posture sees.
        session = FakeSession(responses=[
            FakeResponse(headers={"Server": "nginx/1.18.0"},
                         url="https://example.com/")])
        test = hhs.ResponseHeaderPostureTest("https://example.com/", "example.com",
                                             session=session, timeout=1,
                                             verbose=0, quiet=True)
        test.run()
        types = {f["test_type"] for f in test.vulnerabilities_found}
        self.assertIn("Strict-Transport-Security", types)
        self.assertIn("Version Disclosure", types)


if __name__ == "__main__":
    unittest.main()
