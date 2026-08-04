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
from headerhawk.posture import rules
from tests.helpers import FakeResponse, FakeSession

GOOD = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": ("default-src 'self'; object-src 'none'; "
                                "base-uri 'none'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
    "Server": "nginx",
}


def _assess(test_type, headers, scheme="https"):
    rule = next(r for r in rules.RULES if r.test_type == test_type)
    lowered = {name.lower(): value for name, value in headers.items()}
    return rule.assess(lowered, scheme)


class CleanResponseTests(unittest.TestCase):
    def test_a_well_configured_response_produces_no_findings(self):
        for rule in rules.RULES:
            lowered = {name.lower(): value for name, value in GOOD.items()}
            self.assertIsNone(rule.assess(lowered, "https"),
                              f"{rule.test_type} fired on a clean response")


class HstsTests(unittest.TestCase):
    def test_not_reported_over_plaintext(self):
        # A browser ignores HSTS on an http:// response, so flagging it there
        # would be pure noise.
        self.assertIsNone(_assess("Strict-Transport-Security", {}, scheme="http"))

    def test_missing_over_https(self):
        result, analysis = _assess("Strict-Transport-Security", {})
        self.assertEqual(result, "Missing")
        self.assertIn("Strict-Transport-Security", analysis)

    def test_max_age_below_one_year_is_weak(self):
        result, analysis = _assess("Strict-Transport-Security",
                                   {"Strict-Transport-Security": "max-age=600; includeSubDomains"})
        self.assertEqual(result, "Weak")
        self.assertIn("below the required one year", analysis)

    def test_missing_include_subdomains_is_weak(self):
        result, analysis = _assess("Strict-Transport-Security",
                                   {"Strict-Transport-Security": "max-age=63072000"})
        self.assertEqual(result, "Weak")
        self.assertIn("includeSubDomains", analysis)

    def test_exactly_one_year_is_accepted(self):
        value = f"max-age={rules.ONE_YEAR_SECONDS}; includeSubDomains"
        self.assertIsNone(_assess("Strict-Transport-Security",
                                  {"Strict-Transport-Security": value}))


class CspTests(unittest.TestCase):
    def test_missing(self):
        result, _ = _assess("Content-Security-Policy", {})
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
            "Content-Security-Policy": "default-src 'self'; object-src *; base-uri 'none'"})
        self.assertEqual(result, "Weak")
        self.assertIn("object-src", analysis)


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
        result, _ = _assess("Frame Protection", {})
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


class PostureCheckTests(unittest.TestCase):
    def _run(self, headers, url="https://example.com/"):
        session = FakeSession(responses=[FakeResponse(headers=headers, url=url)])
        test = hhs.ResponseHeaderPostureTest(url, "example.com", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        return test

    def test_clean_response_yields_nothing(self):
        self.assertEqual(self._run(GOOD).vulnerabilities_found, [])

    def test_bare_response_reports_every_control(self):
        found = self._run({}).vulnerabilities_found
        types = {finding["test_type"] for finding in found}
        self.assertIn("Strict-Transport-Security", types)
        self.assertIn("Content-Security-Policy", types)
        self.assertIn("Permissions-Policy", types)

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
