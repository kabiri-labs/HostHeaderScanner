"""Tests for the package layout's backward-compatibility contract.

The tool was split from a single module into a package. Anything that used to
be reachable as ``headerhawk.<name>`` must stay reachable, and the checks must
still run in the order the CLI has always used - these tests are what stops a
future move from silently breaking either.
"""

import unittest

import headerhawk as hhs
from headerhawk.checks.registry import CHECKS, finding_types


class CheckRegistryTests(unittest.TestCase):
    # The order the CLI instantiates checks in is observable: it decides the
    # order findings are printed and written to a report.
    EXPECTED_ORDER = [
        "Response Header Posture",
        "Host Header Injection",
        "Host Header Bypass",
        "Web Cache Poisoning",
        "Unkeyed Input",
        "CORS Misconfiguration",
        "CRLF Injection",
        "Auth Bypass",
        "Virtual Host Discovery",
        "SSRF",
        "URL Parameter SSRF",
        "Open Redirect",
        "HTTP Request Smuggling",
    ]

    def test_registry_order_is_stable(self):
        self.assertEqual([check.test_type for check in CHECKS],
                         self.EXPECTED_ORDER)

    def test_every_check_derives_from_base(self):
        for check in CHECKS:
            self.assertTrue(issubclass(check, hhs.BaseTest), check.__name__)

    def test_every_emitted_type_has_a_severity(self):
        # A finding type missing from the severity map would silently report as
        # the default band instead of its intended one. Checked against every
        # type the scanner can emit, not just each check's own name - a check
        # may report several distinct issues.
        for test_type in finding_types():
            self.assertIn(test_type, hhs.SEVERITY_BY_TEST, test_type)


class PublicSurfaceTests(unittest.TestCase):
    def test_documented_names_are_importable_from_the_package_root(self):
        for name in hhs.__all__:
            self.assertTrue(hasattr(hhs, name), f"headerhawk.{name} is missing")

    def test_registry_classes_are_re_exported(self):
        for check in CHECKS:
            self.assertIs(getattr(hhs, check.__name__), check)


if __name__ == "__main__":
    unittest.main()
