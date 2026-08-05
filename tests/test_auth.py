"""Tests for authenticated scanning and for knowing whether it worked.

The failure this guards against is silent. Pointed at an authenticated product
without a working session, every request comes back as the login page, and the
scanner reports the login page's headers as the product's. Nothing errors. So
the tests below care less about logging in than about the scanner being able to
tell that it did not.
"""

import os
import unittest
from unittest import mock

import requests

import headerhawk as hhs
from headerhawk.core.auth import (FAILED, NOT_CONFIGURED, UNVERIFIED, VERIFIED,
                                  AuthConfig, apply_credentials, is_configured,
                                  log_in, parse_cookie, parse_form_data,
                                  resolve_secret, verify)
from tests.helpers import FakeResponse

LOGGED_IN = "<html>Welcome back. Sign out</html>"
LOGGED_OUT = "<html>Please Sign in</html>"


def _config(**overrides):
    base = dict(cookie=None, login_url=None, login_data=None,
                login_method="POST", verify_text=None, verify_absent=None)
    base.update(overrides)
    return AuthConfig(**base)


class _Session:
    """Session double with a cookie jar and a scripted responder."""

    def __init__(self, responder):
        self.verify = True
        self.headers = {}
        self.proxies = {}
        self.cookies = {}
        self.calls = []
        self._responder = responder

    def request(self, method, url=None, timeout=None, data=None,
                allow_redirects=True, **kwargs):
        self.calls.append({"method": method, "url": url, "data": data})
        result = self._responder(method, url, data, self.cookies)
        if isinstance(result, Exception):
            raise result
        return result


def _app(valid_cookie="good"):
    """A server that only shows the application to a valid session cookie."""
    def responder(method, url, data, cookies):
        if method == "POST":
            if (data or {}).get("pass") == "s3cret":
                cookies["sid"] = valid_cookie
                return FakeResponse(200, text=LOGGED_IN, url=url)
            return FakeResponse(401, text=LOGGED_OUT, url=url)
        if cookies.get("sid") == valid_cookie:
            return FakeResponse(200, text=LOGGED_IN, url=url)
        return FakeResponse(200, text=LOGGED_OUT, url=url)
    return responder


class SecretResolutionTests(unittest.TestCase):
    def test_a_plain_value_is_used_as_is(self):
        self.assertEqual(resolve_secret("user=a&pass=b"), "user=a&pass=b")

    def test_env_prefix_reads_the_environment(self):
        # Keeps a credential out of the command line and out of shell history.
        with mock.patch.dict(os.environ, {"HH_TEST_SECRET": "user=a&pass=b"}):
            self.assertEqual(resolve_secret("env:HH_TEST_SECRET"),
                             "user=a&pass=b")

    def test_a_missing_environment_variable_yields_empty(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_secret("env:NOT_SET_ANYWHERE"), "")


class ParsingTests(unittest.TestCase):
    def test_cookie_string(self):
        self.assertEqual(parse_cookie("a=1; b=2"), {"a": "1", "b": "2"})

    def test_cookie_string_ignores_junk(self):
        self.assertEqual(parse_cookie("a=1; nonsense; =2"), {"a": "1"})

    def test_form_data(self):
        self.assertEqual(parse_form_data("user=a&pass=b"),
                         {"user": "a", "pass": "b"})

    def test_configured_needs_a_cookie_or_a_login(self):
        self.assertFalse(is_configured(None))
        self.assertFalse(is_configured(_config(verify_text="x")))
        self.assertTrue(is_configured(_config(cookie="a=1")))
        self.assertTrue(is_configured(_config(login_url="http://t/login")))


class LoginTests(unittest.TestCase):
    def test_a_correct_login_is_reported_as_authenticated(self):
        session = _Session(_app())
        result = log_in(session, _config(login_url="http://t/login",
                                         login_data="user=admin&pass=s3cret"), 1)
        self.assertEqual(result.state, VERIFIED)
        self.assertEqual(session.cookies.get("sid"), "good")

    def test_a_rejected_login_is_reported_as_failed(self):
        session = _Session(_app())
        result = log_in(session, _config(login_url="http://t/login",
                                         login_data="user=admin&pass=wrong"), 1)
        self.assertEqual(result.state, FAILED)
        self.assertIn("401", result.detail)

    def test_an_unreachable_login_endpoint_is_failed_not_ignored(self):
        session = _Session(lambda *a: requests.ConnectionError("nope"))
        result = log_in(session, _config(login_url="http://t/login",
                                         login_data="user=a&pass=b"), 1)
        self.assertEqual(result.state, FAILED)

    def test_empty_login_data_is_rejected(self):
        session = _Session(_app())
        result = log_in(session, _config(login_url="http://t/login",
                                         login_data=""), 1)
        self.assertEqual(result.state, FAILED)

    def test_a_login_that_sets_no_cookie_is_not_claimed_as_verified(self):
        def responder(method, url, data, cookies):
            return FakeResponse(200, text=LOGGED_IN, url=url)
        result = log_in(_Session(responder),
                        _config(login_url="http://t/login",
                                login_data="user=a&pass=b"), 1)
        self.assertEqual(result.state, UNVERIFIED)

    def test_credentials_read_from_the_environment(self):
        session = _Session(_app())
        with mock.patch.dict(os.environ, {"HH_LOGIN": "user=admin&pass=s3cret"}):
            result = log_in(session, _config(login_url="http://t/login",
                                             login_data="env:HH_LOGIN"), 1)
        self.assertEqual(result.state, VERIFIED)


class VerificationTests(unittest.TestCase):
    def test_no_credentials_means_unauthenticated_not_a_failure(self):
        result = verify(_Session(_app()), "http://t/", None, 1)
        self.assertEqual(result.state, NOT_CONFIGURED)

    def test_expected_text_present_verifies_the_session(self):
        session = _Session(_app())
        config = _config(cookie="sid=good", verify_text="Sign out")
        apply_credentials(session, config)
        self.assertEqual(verify(session, "http://t/", config, 1).state, VERIFIED)

    def test_a_bogus_cookie_is_caught(self):
        # The case the whole module exists for: a session that is not a session.
        session = _Session(_app())
        config = _config(cookie="sid=bogus", verify_text="Sign out")
        apply_credentials(session, config)
        result = verify(session, "http://t/", config, 1)
        self.assertEqual(result.state, FAILED)
        self.assertIn("not logged in", result.detail)

    def test_verify_absent_is_the_inverse(self):
        session = _Session(_app())
        config = _config(cookie="sid=good", verify_absent="Sign in")
        apply_credentials(session, config)
        self.assertEqual(verify(session, "http://t/", config, 1).state, VERIFIED)

    def test_verify_absent_catches_a_logged_out_session(self):
        session = _Session(_app())
        config = _config(cookie="sid=bogus", verify_absent="Sign in")
        apply_credentials(session, config)
        self.assertEqual(verify(session, "http://t/", config, 1).state, FAILED)

    def test_an_unreachable_target_is_not_reported_as_authenticated(self):
        session = _Session(lambda *a: requests.ConnectionError("nope"))
        config = _config(cookie="sid=good", verify_text="Sign out")
        self.assertEqual(verify(session, "http://t/", config, 1).state, FAILED)


class DifferentialVerificationTests(unittest.TestCase):
    """With no expectation given, ask whether the credentials changed anything."""

    def test_credentials_that_change_the_response_verify_it(self):
        responder = _app()
        session = _Session(responder)
        config = _config(cookie="sid=good")
        apply_credentials(session, config)
        result = verify(session, "http://t/", config, 1,
                        session_factory=lambda: _Session(responder))
        self.assertEqual(result.state, VERIFIED)

    def test_credentials_that_change_nothing_are_flagged_not_trusted(self):
        # A public page looks the same either way; that is not an error, but the
        # scan is then not assessing the authenticated surface and must say so.
        def same_either_way(method, url, data, cookies):
            return FakeResponse(200, text="<html>public</html>", url=url)
        session = _Session(same_either_way)
        config = _config(cookie="sid=whatever")
        result = verify(session, "http://t/", config, 1,
                        session_factory=lambda: _Session(same_either_way))
        self.assertEqual(result.state, UNVERIFIED)
        self.assertIn("--auth-verify-text", result.detail)

    def test_without_a_comparison_session_it_stays_unverified(self):
        session = _Session(_app())
        config = _config(cookie="sid=good")
        apply_credentials(session, config)
        self.assertEqual(verify(session, "http://t/", config, 1).state, UNVERIFIED)


class EvidenceTests(unittest.TestCase):
    def test_the_scan_mode_is_recorded(self):
        evidence = hhs.build_evidence([], ["http://t/"], scan_mode=VERIFIED)
        self.assertEqual(evidence["scan_mode"], VERIFIED)

    def test_an_unverified_scan_is_called_out_in_the_report(self):
        body = hhs.render_markdown(
            hhs.build_evidence([], ["http://t/"], scan_mode=UNVERIFIED))
        self.assertIn("Scan mode:", body)
        self.assertIn("not confirmed to be running as a logged-in user", body)

    def test_an_authenticated_scan_carries_no_such_warning(self):
        body = hhs.render_markdown(
            hhs.build_evidence([], ["http://t/"], scan_mode=VERIFIED))
        self.assertNotIn("not confirmed to be running", body)


class CliTests(unittest.TestCase):
    def _args(self, *extra):
        with mock.patch("sys.argv", ["prog", "http://t/", *extra]):
            return hhs.parse_arguments()

    def test_authentication_is_off_by_default(self):
        args = self._args()
        self.assertIsNone(args.auth_cookie)
        self.assertIsNone(args.auth_login_url)

    def test_every_option_is_accepted(self):
        args = self._args("--auth-cookie", "a=1",
                          "--auth-login-url", "http://t/login",
                          "--auth-login-data", "env:X",
                          "--auth-verify-text", "Sign out")
        self.assertEqual(args.auth_cookie, "a=1")
        self.assertEqual(args.auth_login_url, "http://t/login")
        self.assertEqual(args.auth_login_data, "env:X")
        self.assertEqual(args.auth_verify_text, "Sign out")

    def test_login_method_defaults_to_post(self):
        self.assertEqual(self._args().auth_login_method, "POST")


if __name__ == "__main__":
    unittest.main()
