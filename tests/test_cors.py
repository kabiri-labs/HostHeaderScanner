"""Tests for the active CORS origin-validation check.

The properties that matter: a finding is only made when the server echoed an
origin the scanner chose (so it is proof, not suspicion), a permissive
allowlist is not reported five times over for the same root cause, and a
correctly configured allowlist produces nothing at all.
"""

import unittest

import headerhawk as hhs
from headerhawk.checks.cors import ALLOW_CREDENTIALS, ALLOW_ORIGIN, CORSTest
from tests.helpers import FakeResponse, FakeSession


class _ScriptedSession:
    """Session double that answers according to the Origin it is sent.

    ``responder`` receives the request's Origin and returns the response
    headers, which is how these tests express a server's allowlist policy.
    """

    def __init__(self, responder, status_code=200):
        self.verify = True
        self.headers = {}
        self.proxies = {}
        self.origins = []
        self._responder = responder
        self._status = status_code

    def request(self, method, url=None, headers=None, timeout=None,
                allow_redirects=True, data=None, **kwargs):
        origin = (headers or {}).get("Origin")
        self.origins.append(origin)
        return FakeResponse(status_code=self._status,
                            headers=self._responder(origin) or {},
                            url=url)


def _make(session, url="https://example.com/", host="example.com"):
    return CORSTest(url, host, session=session, timeout=1, verbose=0, quiet=True)


def _reflect_everything(credentials=True):
    def responder(origin):
        headers = {ALLOW_ORIGIN: origin}
        if credentials:
            headers[ALLOW_CREDENTIALS] = "true"
        return headers
    return responder


def _run(responder, **kwargs):
    session = _ScriptedSession(responder)
    test = _make(session, **kwargs)
    test.run()
    return test


class NoCorsTests(unittest.TestCase):
    def test_absent_cors_headers_produce_nothing(self):
        self.assertEqual(_run(lambda origin: {}).vulnerabilities_found, [])

    def test_a_fixed_allowlist_produces_nothing(self):
        # The correct configuration: one fixed value, whatever is asked for.
        def responder(origin):
            return {ALLOW_ORIGIN: "https://app.example.com",
                    ALLOW_CREDENTIALS: "true"}
        self.assertEqual(_run(responder).vulnerabilities_found, [])

    def test_bare_wildcard_alone_is_not_reported(self):
        # "*" without credentials is the correct configuration for a public
        # endpoint; reporting it everywhere would be noise.
        self.assertEqual(
            _run(lambda origin: {ALLOW_ORIGIN: "*"}).vulnerabilities_found, [])

    def test_unreachable_target_reports_nothing(self):
        test = _make(FakeSession(responses=[]))
        test.session = FakeSession(responses=[])
        # Every probe fails; request() turns that into None.
        test.probe = lambda origin: (None, False)
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])


class ReflectionTests(unittest.TestCase):
    def test_reflected_arbitrary_origin_is_high_with_credentials(self):
        found = _run(_reflect_everything(credentials=True)).vulnerabilities_found
        reflection = next(f for f in found
                          if f["test_type"] == CORSTest.REFLECTION)
        self.assertEqual(reflection["severity"], "High")
        self.assertIn("cannot exist", reflection["analysis"])
        self.assertIn("read authenticated responses", reflection["analysis"])

    def test_reflected_arbitrary_origin_is_medium_without_credentials(self):
        found = _run(_reflect_everything(credentials=False)).vulnerabilities_found
        reflection = next(f for f in found
                          if f["test_type"] == CORSTest.REFLECTION)
        self.assertEqual(reflection["severity"], "Medium")
        self.assertIn("only unauthenticated content", reflection["analysis"])

    def test_reflection_does_not_restate_itself_as_five_findings(self):
        # A server that echoes anything would match every narrower probe too;
        # reporting each would be the same root cause five times over.
        found = _run(_reflect_everything()).vulnerabilities_found
        types = [f["test_type"] for f in found]
        self.assertNotIn(CORSTest.VALIDATION_BYPASS, types)
        self.assertNotIn(CORSTest.INSECURE_ORIGIN, types)

    def test_null_is_still_probed_when_everything_reflects(self):
        # Trusting null is a separate decision with a separate fix.
        found = _run(_reflect_everything()).vulnerabilities_found
        self.assertIn(CORSTest.NULL_ORIGIN, [f["test_type"] for f in found])

    def test_marker_origin_is_unique_per_scan(self):
        first = _make(_ScriptedSession(lambda o: {}))
        second = _make(_ScriptedSession(lambda o: {}))
        self.assertNotEqual(first.token, second.token)


class NullOriginTests(unittest.TestCase):
    def test_null_only(self):
        def responder(origin):
            if origin == "null":
                return {ALLOW_ORIGIN: "null", ALLOW_CREDENTIALS: "true"}
            return {}
        found = _run(responder).vulnerabilities_found
        self.assertEqual([f["test_type"] for f in found], [CORSTest.NULL_ORIGIN])
        self.assertEqual(found[0]["severity"], "High")
        self.assertIn("sandboxed iframe", found[0]["analysis"])


class ValidationBypassTests(unittest.TestCase):
    def _bypass(self, predicate, credentials=True):
        def responder(origin):
            if origin and predicate(origin):
                headers = {ALLOW_ORIGIN: origin}
                if credentials:
                    headers[ALLOW_CREDENTIALS] = "true"
                return headers
            return {}
        return _run(responder).vulnerabilities_found

    def test_prefix_match(self):
        found = self._bypass(lambda o: o.startswith("https://example.com"))
        analyses = [f["analysis"] for f in found
                    if f["test_type"] == CORSTest.VALIDATION_BYPASS]
        self.assertTrue(any("prefix" in a for a in analyses), analyses)

    def test_suffix_match_without_a_dot_anchor(self):
        found = self._bypass(lambda o: o.endswith("example.com")
                             and not o.startswith("https://example.com"))
        analyses = [f["analysis"] for f in found
                    if f["test_type"] == CORSTest.VALIDATION_BYPASS]
        self.assertTrue(any("suffix" in a for a in analyses), analyses)

    def test_trailing_dot(self):
        found = self._bypass(lambda o: o == "https://example.com.")
        self.assertEqual(len(found), 1)
        self.assertIn("trailing dot", found[0]["analysis"])

    def test_any_subdomain_trusted(self):
        found = self._bypass(lambda o: o.endswith(".example.com"))
        self.assertEqual(len(found), 1)
        self.assertIn("subdomain", found[0]["analysis"])

    def test_severity_drops_without_credentials(self):
        found = self._bypass(lambda o: o == "https://example.com.",
                             credentials=False)
        self.assertEqual(found[0]["severity"], "Medium")


class SchemeDowngradeTests(unittest.TestCase):
    def test_https_endpoint_trusting_its_plaintext_origin(self):
        def responder(origin):
            if origin == "http://example.com":
                return {ALLOW_ORIGIN: origin, ALLOW_CREDENTIALS: "true"}
            return {}
        found = _run(responder).vulnerabilities_found
        self.assertEqual([f["test_type"] for f in found],
                         [CORSTest.INSECURE_ORIGIN])
        self.assertIn("plaintext origin", found[0]["analysis"])

    def test_not_probed_for_a_plaintext_target(self):
        # There is no downgrade to find when the target is already plaintext.
        session = _ScriptedSession(lambda origin: {})
        test = _make(session, url="http://example.com/")
        test.run()
        self.assertNotIn("http://example.com", session.origins[1:])


class WildcardWithCredentialsTests(unittest.TestCase):
    def _wildcard_run(self):
        return _run(lambda origin: {ALLOW_ORIGIN: "*",
                                    ALLOW_CREDENTIALS: "true"})

    def test_reported_once_not_once_per_probe(self):
        found = self._wildcard_run().vulnerabilities_found
        wildcard = [f for f in found
                    if f["test_type"] == CORSTest.WILDCARD_CREDENTIALS]
        self.assertEqual(len(wildcard), 1)

    def test_reported_as_low_because_a_browser_refuses_it(self):
        found = self._wildcard_run().vulnerabilities_found
        wildcard = next(f for f in found
                        if f["test_type"] == CORSTest.WILDCARD_CREDENTIALS)
        self.assertEqual(wildcard["severity"], "Low")
        self.assertIn("refuses that combination", wildcard["analysis"])


class FindingShapeTests(unittest.TestCase):
    def test_findings_are_vulnerability_class_and_carry_the_control(self):
        found = _run(_reflect_everything()).vulnerabilities_found
        for finding in found:
            self.assertEqual(finding["finding_class"], hhs.CLASS_VULNERABILITY)
            self.assertEqual(finding["controls"], ["ASVS-5.0:3.4.2"])

    def test_reproduction_command_carries_the_origin(self):
        found = _run(_reflect_everything()).vulnerabilities_found
        reflection = next(f for f in found
                          if f["test_type"] == CORSTest.REFLECTION)
        self.assertIn("-H 'Origin: ", reflection["repro"])
        self.assertIn(reflection["payload"], reflection["repro"])


if __name__ == "__main__":
    unittest.main()
