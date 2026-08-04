"""Tests for the response-header posture rules and the finding-class gate.

Two properties matter most here. A rule must stay quiet when the control is
genuinely in place - a posture report that cries wolf gets ignored, which costs
more than the finding was worth. And posture findings must not fail a build
unless the caller asked for it, because adding this check should not turn every
existing pipeline red.
"""

import unittest
from unittest import mock

import requests

import headerhawk as hhs
from headerhawk.core.findings import CLASS_POSTURE, CLASS_VULNERABILITY
from headerhawk.posture import cookies as cookie_mod
from headerhawk.posture import rules
from headerhawk.posture.facts import ResponseFacts
from tests.helpers import FakeResponse, FakeSession

# A response that satisfies every rule, so any rule firing against it is a
# false positive by definition.
GOOD = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "report-to csp-endpoint"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
    "Server": "nginx",
}

GOOD_COOKIE = ("__Host-session=abc; Secure; HttpOnly; SameSite=Lax; Path=/")


def _facts(headers, scheme="https", cookies=()):
    parsed = [cookie_mod.parse_set_cookie(raw) for raw in cookies]
    return ResponseFacts(
        url=f"{scheme}://example.com/", scheme=scheme, status_code=200,
        headers={name.lower(): value for name, value in headers.items()},
        cookies=[cookie for cookie in parsed if cookie])


def _rule(test_type):
    return next(r for r in rules.RULES if r.test_type == test_type)


def _issues(test_type, headers=None, scheme="https", cookies=()):
    return _rule(test_type).assess(_facts(headers or {}, scheme, cookies))


def _assess(test_type, headers=None, scheme="https", cookies=()):
    """Return (test_result, analysis) for a rule expected to yield one issue."""
    found = _issues(test_type, headers, scheme, cookies)
    if not found:
        return None
    assert len(found) == 1, f"expected one issue, got {len(found)}"
    return found[0].test_result, found[0].analysis


class CleanResponseTests(unittest.TestCase):
    def test_a_well_configured_response_produces_no_findings(self):
        facts = _facts(GOOD, cookies=[GOOD_COOKIE])
        for rule in rules.RULES:
            self.assertEqual(rule.assess(facts), [],
                             f"{rule.test_type} fired on a clean response")


class HstsTests(unittest.TestCase):
    def test_not_reported_over_plaintext(self):
        # A browser ignores HSTS on an http:// response, so flagging it there
        # would be pure noise.
        self.assertIsNone(_assess("Strict-Transport-Security", scheme="http"))

    def test_missing_over_https(self):
        result, analysis = _assess("Strict-Transport-Security")
        self.assertEqual(result, "Missing")
        self.assertIn("Strict-Transport-Security", analysis)

    def test_max_age_below_one_year_is_weak(self):
        result, analysis = _assess(
            "Strict-Transport-Security",
            {"Strict-Transport-Security": "max-age=600; includeSubDomains"})
        self.assertEqual(result, "Weak")
        self.assertIn("below the required one year", analysis)

    def test_missing_include_subdomains_is_weak(self):
        result, analysis = _assess(
            "Strict-Transport-Security",
            {"Strict-Transport-Security": "max-age=63072000"})
        self.assertEqual(result, "Weak")
        self.assertIn("includeSubDomains", analysis)

    def test_exactly_one_year_is_accepted(self):
        value = f"max-age={rules.ONE_YEAR_SECONDS}; includeSubDomains"
        self.assertIsNone(_assess("Strict-Transport-Security",
                                  {"Strict-Transport-Security": value}))


class CspTests(unittest.TestCase):
    def test_missing(self):
        result, _ = _assess("Content-Security-Policy")
        self.assertEqual(result, "Missing")

    def test_default_src_none_satisfies_object_src(self):
        # object-src falls back to default-src, so this policy meets 3.4.3.
        self.assertIsNone(_assess("Content-Security-Policy", {
            "Content-Security-Policy": "default-src 'none'; base-uri 'none'"}))

    def test_default_src_none_does_not_satisfy_base_uri(self):
        # base-uri has no fallback; it must be set explicitly.
        result, analysis = _assess("Content-Security-Policy", {
            "Content-Security-Policy": "default-src 'none'"})
        self.assertEqual(result, "Weak")
        self.assertIn("base-uri", analysis)

    def test_permissive_object_src_is_weak(self):
        result, analysis = _assess("Content-Security-Policy", {
            "Content-Security-Policy":
                "default-src 'self'; object-src *; base-uri 'none'"})
        self.assertEqual(result, "Weak")
        self.assertIn("object-src", analysis)


class CspScriptSourceTests(unittest.TestCase):
    def _script(self, policy):
        return _assess("CSP Script Sources", {"Content-Security-Policy": policy})

    def test_silent_when_no_policy_at_all(self):
        # The presence rule already reports that; saying it twice is noise.
        self.assertIsNone(_assess("CSP Script Sources"))

    def test_no_script_src_and_no_default_src(self):
        result, analysis = self._script("base-uri 'none'")
        self.assertEqual(result, "Weak")
        self.assertIn("default-src", analysis)

    def test_unsafe_inline_is_reported(self):
        result, analysis = self._script("script-src 'self' 'unsafe-inline'")
        self.assertEqual(result, "Weak")
        self.assertIn("unsafe-inline", analysis)

    def test_unsafe_inline_with_a_nonce_is_not_reported(self):
        # A browser ignores 'unsafe-inline' when a nonce is present, so
        # reporting it here would be wrong, not merely noisy.
        self.assertIsNone(self._script(
            "script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'"))

    def test_unsafe_inline_with_a_hash_is_not_reported(self):
        self.assertIsNone(self._script(
            "script-src 'self' 'unsafe-inline' 'sha256-abcdef='"))

    def test_unsafe_eval_is_reported(self):
        result, analysis = self._script("script-src 'self' 'unsafe-eval'")
        self.assertEqual(result, "Weak")
        self.assertIn("unsafe-eval", analysis)

    def test_broad_sources_are_reported(self):
        result, analysis = self._script("script-src 'self' https: *")
        self.assertEqual(result, "Weak")
        self.assertIn("anywhere", analysis)

    def test_strict_dynamic_neutralises_broad_sources(self):
        # With 'strict-dynamic' a browser ignores host and scheme allowlists.
        self.assertIsNone(self._script(
            "script-src 'nonce-r4nd0m' 'strict-dynamic' https: *"))

    def test_scoped_wildcard_host_is_not_a_finding(self):
        # "*.example.com" is an allowlist, not an open door.
        self.assertIsNone(self._script("script-src 'self' *.example.com"))

    def test_falls_back_to_default_src(self):
        result, analysis = self._script("default-src 'self' 'unsafe-eval'")
        self.assertEqual(result, "Weak")
        self.assertIn("unsafe-eval", analysis)


class CspReportingTests(unittest.TestCase):
    def test_silent_without_a_policy(self):
        self.assertIsNone(_assess("CSP Violation Reporting"))

    def test_missing_reporting_location(self):
        result, _ = _assess("CSP Violation Reporting",
                            {"Content-Security-Policy": "default-src 'none'"})
        self.assertEqual(result, "Missing")

    def test_report_uri_satisfies_it(self):
        self.assertIsNone(_assess("CSP Violation Reporting", {
            "Content-Security-Policy": "default-src 'none'; report-uri /csp"}))

    def test_report_to_satisfies_it(self):
        self.assertIsNone(_assess("CSP Violation Reporting", {
            "Content-Security-Policy": "default-src 'none'; report-to group"}))


class FrameProtectionTests(unittest.TestCase):
    def test_frame_ancestors_is_enough(self):
        self.assertIsNone(_assess("Frame Protection", {
            "Content-Security-Policy": "frame-ancestors 'none'"}))

    def test_only_x_frame_options_is_weak(self):
        result, analysis = _assess("Frame Protection",
                                   {"X-Frame-Options": "SAMEORIGIN"})
        self.assertEqual(result, "Weak")
        self.assertIn("frame-ancestors", analysis)

    def test_neither_is_missing(self):
        result, _ = _assess("Frame Protection")
        self.assertEqual(result, "Missing")

    def test_unusable_x_frame_options_value_is_missing(self):
        result, _ = _assess("Frame Protection", {"X-Frame-Options": "ALLOWALL"})
        self.assertEqual(result, "Missing")


class OtherHeaderTests(unittest.TestCase):
    def test_content_type_options_wrong_value(self):
        result, _ = _assess("X-Content-Type-Options",
                            {"X-Content-Type-Options": "none"})
        self.assertEqual(result, "Weak")

    def test_referrer_policy_unsafe_url(self):
        result, _ = _assess("Referrer-Policy", {"Referrer-Policy": "unsafe-url"})
        self.assertEqual(result, "Weak")

    def test_coop_wrong_value(self):
        result, _ = _assess("Cross-Origin-Opener-Policy",
                            {"Cross-Origin-Opener-Policy": "unsafe-none"})
        self.assertEqual(result, "Weak")


class VersionDisclosureTests(unittest.TestCase):
    def test_bare_product_name_is_not_a_finding(self):
        self.assertIsNone(_assess("Version Disclosure", {"Server": "cloudflare"}))

    def test_version_in_server_header(self):
        result, analysis = _assess("Version Disclosure", {"Server": "nginx/1.18.0"})
        self.assertEqual(result, "Exposed")
        self.assertIn("nginx/1.18.0", analysis)

    def test_version_in_x_powered_by(self):
        result, analysis = _assess("Version Disclosure",
                                   {"X-Powered-By": "PHP/8.2.1"})
        self.assertEqual(result, "Exposed")
        self.assertIn("PHP/8.2.1", analysis)


class SetCookieParsingTests(unittest.TestCase):
    def test_parses_name_value_and_attributes(self):
        cookie = cookie_mod.parse_set_cookie(
            "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")
        self.assertEqual(cookie.name, "sid")
        self.assertEqual(cookie.value, "abc123")
        self.assertIs(cookie.attributes["secure"], True)
        self.assertEqual(cookie.attributes["samesite"], "Strict")

    def test_rejects_a_value_with_no_name(self):
        self.assertIsNone(cookie_mod.parse_set_cookie("just-a-flag; Secure"))

    def test_split_does_not_tear_an_expires_date_apart(self):
        # The comma inside an Expires date is the classic way a naive split
        # invents a second, malformed cookie.
        raw = ("a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/, "
               "b=2; Secure")
        parts = cookie_mod.split_set_cookie(raw)
        self.assertEqual(len(parts), 2)
        self.assertTrue(parts[0].startswith("a=1"))
        self.assertTrue(parts[1].startswith("b=2"))

    def test_prefers_the_structured_header_list(self):
        class RawHeaders:
            @staticmethod
            def getlist(name):
                return ["a=1; Secure", "b=2; HttpOnly"]

        class Response:
            raw = type("R", (), {"headers": RawHeaders()})()
            headers = {"Set-Cookie": "ignored=yes"}

        self.assertEqual(cookie_mod.set_cookie_values(Response()),
                         ["a=1; Secure", "b=2; HttpOnly"])

    def test_falls_back_to_unfolding_the_joined_value(self):
        class Response:
            raw = None
            headers = {"Set-Cookie": "a=1; Secure, b=2; HttpOnly"}

        self.assertEqual(cookie_mod.set_cookie_values(Response()),
                         ["a=1; Secure", "b=2; HttpOnly"])


class CookieRuleTests(unittest.TestCase):
    def test_secure_missing(self):
        result, analysis = _assess("Cookie Secure Attribute",
                                   cookies=["__Host-sid=a; HttpOnly; SameSite=Lax"])
        self.assertEqual(result, "Missing")
        self.assertIn("__Host-sid", analysis)

    def test_secure_not_reported_over_plaintext(self):
        # A Secure cookie would never be sent back over http, so advising it
        # there would be advising a broken site.
        self.assertIsNone(_assess("Cookie Secure Attribute", scheme="http",
                                  cookies=["sid=a"]))

    def test_http_only_reported_for_a_session_looking_cookie(self):
        result, analysis = _assess("Cookie HttpOnly Attribute",
                                   cookies=["__Host-session=a; Secure; SameSite=Lax"])
        self.assertEqual(result, "Missing")
        self.assertIn("session", analysis)

    def test_http_only_recognises_run_together_session_names(self):
        # These are the names real applications use. An earlier version required
        # a separator around the keyword and so missed every one of them.
        for name in ("sessionid", "PHPSESSID", "JSESSIONID", "connect.sid",
                     "authtoken", "access_token", "jwt", "remember_me"):
            with self.subTest(name=name):
                found = _issues("Cookie HttpOnly Attribute",
                                cookies=[f"{name}=a; Secure; SameSite=Lax"])
                self.assertEqual(len(found), 1, f"{name} was not treated as sensitive")

    def test_http_only_leaves_ordinary_names_alone(self):
        for name in ("theme", "lang", "_ga", "cart_items", "consent"):
            with self.subTest(name=name):
                self.assertEqual(
                    _issues("Cookie HttpOnly Attribute",
                            cookies=[f"{name}=a; Secure; SameSite=Lax"]), [])

    def test_http_only_not_reported_for_an_ordinary_cookie(self):
        # An analytics cookie legitimately needs script access; 3.3.4 scopes the
        # requirement to session and sensitive values.
        self.assertEqual(
            _issues("Cookie HttpOnly Attribute",
                    cookies=["__Host-theme=dark; Secure; SameSite=Lax"]), [])

    def test_same_site_missing(self):
        result, _ = _assess("Cookie SameSite Attribute",
                            cookies=["__Host-sid=a; Secure; HttpOnly"])
        self.assertEqual(result, "Missing")

    def test_name_prefix_missing(self):
        result, analysis = _assess("Cookie Name Prefix",
                                   cookies=["sid=a; Secure; HttpOnly; SameSite=Lax"])
        self.assertEqual(result, "Missing")
        self.assertIn("__Host-", analysis)

    def test_secure_prefix_is_accepted(self):
        self.assertIsNone(_assess(
            "Cookie Name Prefix",
            cookies=["__Secure-sid=a; Secure; HttpOnly; SameSite=Lax"]))

    def test_oversized_cookie(self):
        big = "x" * 5000
        result, analysis = _assess("Cookie Size",
                                   cookies=[f"__Host-blob={big}; Secure"])
        self.assertEqual(result, "Oversized")
        self.assertIn("above the 4096-byte limit", analysis)

    def test_size_accepts_an_ordinary_cookie(self):
        self.assertIsNone(_assess("Cookie Size", cookies=[GOOD_COOKIE]))

    def test_one_issue_per_failing_cookie(self):
        found = _issues("Cookie SameSite Attribute",
                        cookies=["__Host-a=1; Secure", "__Host-b=2; Secure"])
        self.assertEqual(len(found), 2)
        self.assertNotEqual(found[0].subject, found[1].subject)


class PostureCheckTests(unittest.TestCase):
    def _run(self, headers, url="https://example.com/"):
        session = FakeSession(responses=[FakeResponse(headers=headers, url=url)])
        test = hhs.ResponseHeaderPostureTest(url, "example.com", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        return test

    def test_clean_response_yields_nothing(self):
        headers = dict(GOOD, **{"Set-Cookie": GOOD_COOKIE})
        self.assertEqual(self._run(headers).vulnerabilities_found, [])

    def test_bare_response_reports_every_control(self):
        found = self._run({}).vulnerabilities_found
        types = {finding["test_type"] for finding in found}
        self.assertIn("Strict-Transport-Security", types)
        self.assertIn("Content-Security-Policy", types)
        self.assertIn("Permissions-Policy", types)

    def test_cookie_findings_reach_the_report(self):
        found = self._run({"Set-Cookie": "sid=abc"}).vulnerabilities_found
        by_type = {finding["test_type"]: finding for finding in found}
        self.assertIn("Cookie Secure Attribute", by_type)
        self.assertEqual(by_type["Cookie Secure Attribute"]["header_name"],
                         "Set-Cookie: sid")
        self.assertEqual(by_type["Cookie HttpOnly Attribute"]["controls"],
                         ["ASVS-5.0:3.3.4"])

    def test_findings_are_posture_class_and_carry_controls(self):
        found = self._run({}).vulnerabilities_found
        for finding in found:
            self.assertEqual(finding["finding_class"], CLASS_POSTURE)
        hsts = next(f for f in found
                    if f["test_type"] == "Strict-Transport-Security")
        self.assertEqual(hsts["controls"], ["ASVS-5.0:3.4.1"])

    def test_assessment_follows_redirects_and_records_the_final_url(self):
        test = self._run({}, url="https://example.com/landing")
        self.assertTrue(all(f["url"] == "https://example.com/landing"
                            for f in test.vulnerabilities_found))

    def test_unreachable_target_reports_nothing(self):
        # A failed request must not read as "no controls are missing"; the check
        # has to stay silent rather than report a clean posture it never saw.
        session = FakeSession(responses=[requests.RequestException()])
        test = hhs.ResponseHeaderPostureTest("https://example.com/", "example.com",
                                             session=session, timeout=1, quiet=True)
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])


class _ClassStub:
    def __init__(self, findings):
        self.vulnerabilities_found = findings


class FailOnTests(unittest.TestCase):
    TESTS = [_ClassStub([
        {"finding_class": CLASS_VULNERABILITY},
        {"finding_class": CLASS_POSTURE},
        {"finding_class": CLASS_POSTURE},
    ])]

    def test_default_counts_only_vulnerabilities(self):
        self.assertEqual(hhs.gated_finding_count(self.TESTS), 1)
        self.assertEqual(hhs.gated_finding_count(self.TESTS, "vuln"), 1)

    def test_posture_counts_only_posture(self):
        self.assertEqual(hhs.gated_finding_count(self.TESTS, "posture"), 2)

    def test_any_counts_both(self):
        self.assertEqual(hhs.gated_finding_count(self.TESTS, "any"), 3)

    def test_none_never_fails(self):
        self.assertEqual(hhs.gated_finding_count(self.TESTS, "none"), 0)

    def test_unknown_setting_counts_nothing(self):
        # Failing a build because of a typo would be the worse mistake.
        self.assertEqual(hhs.gated_finding_count(self.TESTS, "nonsense"), 0)

    def test_findings_without_a_class_count_as_vulnerabilities(self):
        legacy = [_ClassStub([{"test_type": "SSRF"}])]
        self.assertEqual(hhs.gated_finding_count(legacy, "vuln"), 1)

    def test_counts_by_class(self):
        counts = hhs.count_by_class(self.TESTS)
        self.assertEqual(counts[CLASS_VULNERABILITY], 1)
        self.assertEqual(counts[CLASS_POSTURE], 2)


class FailOnCliTests(unittest.TestCase):
    def test_default_is_vuln(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            self.assertEqual(hhs.parse_arguments().fail_on, "vuln")

    def test_accepts_every_documented_choice(self):
        for choice in ("vuln", "posture", "any", "none"):
            with mock.patch("sys.argv", ["prog", "http://t/", "--fail-on", choice]):
                self.assertEqual(hhs.parse_arguments().fail_on, choice)


if __name__ == "__main__":
    unittest.main()
