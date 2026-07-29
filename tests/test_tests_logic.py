"""Tests for the detection logic inside the individual test classes.

These exercise payload generation, response analysis and the reflection/redirect
decision code by driving the workers with queued fake responses - never the
network.
"""

import unittest

import host_header_scanner as hhs
from tests.helpers import FakeResponse, FakeSession


def make_test(cls, session, target="http://example.com/", host="example.com",
              **overrides):
    kwargs = dict(session=session, methods=["GET"], threads=1, verbose=1,
                  timeout=1)
    kwargs.update(overrides)
    return cls(target, host, **kwargs)


class HostInjectionMarkerTests(unittest.TestCase):
    def test_markers_include_bypass_shapes(self):
        test = make_test(hhs.HostInjectionTest, FakeSession())
        token, markers = test.generate_markers()
        base = next(m for m in markers if m.startswith(token))
        self.assertIn(f"example.com.{base}", markers)
        self.assertIn(f"example.com@{base}", markers)

    def test_marker_uses_oob_manager_host(self):
        manager = hhs.OOBManager("oob.example.com")
        test = make_test(hhs.HostInjectionTest, FakeSession(), oob_manager=manager)
        _, markers = test.generate_markers()
        self.assertTrue(any("oob.example.com" in m for m in markers))

    def test_worker_records_body_reflection(self):
        test = make_test(hhs.HostInjectionTest, FakeSession())
        test.marker_token = "deadbeef"
        test.request = lambda *a, **k: FakeResponse(
            text="prefix deadbeef suffix", url="http://example.com/")
        test.worker("GET", "X-Forwarded-Host", "deadbeef.example-collab.com")
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertIn("response body", test.vulnerabilities_found[0]["analysis"])

    def test_worker_ignores_unreflected(self):
        test = make_test(hhs.HostInjectionTest, FakeSession())
        test.marker_token = "deadbeef"
        test.request = lambda *a, **k: FakeResponse(text="nothing here")
        test.worker("GET", "Host", "deadbeef.example-collab.com")
        self.assertEqual(test.vulnerabilities_found, [])


class SSRFLogicTests(unittest.TestCase):
    def test_generate_payloads_includes_host_port_combos(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        payloads = test.generate_payloads()
        self.assertIn("169.254.169.254", payloads)
        self.assertIn("127.0.0.1:8080", payloads)

    def test_header_anomalies_flag_new_and_changed(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test.baseline_headers = {"Server": "nginx", "X-Env": "prod"}
        anomalies = test.detect_header_anomalies({
            "Server": "nginx",          # excluded -> ignored
            "X-Env": "staging",         # changed
            "X-New": "1",               # new
        })
        self.assertIn("'X-Env' changed", anomalies)
        self.assertIn("new header 'X-New'", anomalies)

    def test_analyze_records_high_score_indicator(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test.typical_delay = 0.1
        test.results = [{
            "url": "http://example.com/",
            "method": "GET",
            "header_name": "Host",
            "payload": "169.254.169.254",
            "status_code": 200,
            "response_time": 0.1,
            "response_body": "root:x:0:0:root:/root:/bin/bash",
            "response_headers": {},
        }]
        test.analyze()
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertIn("root:x:0:0:", test.vulnerabilities_found[0]["analysis"])

    def test_analyze_ignores_low_score(self):
        test = make_test(hhs.SSRFTest, FakeSession())
        test.typical_delay = 0.1
        test.results = [{
            "url": "http://example.com/", "method": "GET",
            "header_name": "Host", "payload": "127.0.0.1", "status_code": 200,
            "response_time": 0.1, "response_body": "ok", "response_headers": {},
        }]
        test.analyze()
        self.assertEqual(test.vulnerabilities_found, [])


class OpenRedirectTests(unittest.TestCase):
    def test_payloads_prepend_oob(self):
        manager = hhs.OOBManager("oob.example.com")
        test = make_test(hhs.OpenRedirectTest, FakeSession(), oob_manager=manager)
        payloads = test.generate_payloads()
        self.assertIn("oob.example.com", payloads[0])

    def test_worker_records_matching_redirect(self):
        test = make_test(hhs.OpenRedirectTest, FakeSession())
        test.request = lambda *a, **k: FakeResponse(
            status_code=302, headers={"Location": "http://example.com/"},
            url="http://example.com/")
        test.worker("GET", "Host", "example.com")
        self.assertEqual(len(test.vulnerabilities_found), 1)

    def test_worker_ignores_non_matching_host(self):
        test = make_test(hhs.OpenRedirectTest, FakeSession())
        test.request = lambda *a, **k: FakeResponse(
            status_code=302, headers={"Location": "http://real-site/"})
        test.worker("GET", "Host", "example.com")
        self.assertEqual(test.vulnerabilities_found, [])

    def test_worker_ignores_non_redirect_status(self):
        test = make_test(hhs.OpenRedirectTest, FakeSession())
        test.request = lambda *a, **k: FakeResponse(status_code=200)
        test.worker("GET", "Host", "example.com")
        self.assertEqual(test.vulnerabilities_found, [])


class URLParameterTests(unittest.TestCase):
    def test_is_response_different_by_status(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        test.baseline_response = FakeResponse(status_code=200, text="x" * 100)
        self.assertTrue(test.is_response_different(FakeResponse(status_code=500, text="x" * 100)))

    def test_is_response_different_by_length(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        test.baseline_response = FakeResponse(status_code=200, text="x" * 100)
        self.assertTrue(test.is_response_different(FakeResponse(status_code=200, text="x" * 200)))

    def test_is_response_same(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        test.baseline_response = FakeResponse(status_code=200, text="x" * 100)
        self.assertFalse(test.is_response_different(FakeResponse(status_code=200, text="x" * 100)))

    def test_analyze_response_scores_indicator(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        analysis = test.analyze_response(FakeResponse(text="root:x:0:0:root"))
        self.assertIsNotNone(analysis)
        self.assertIn("root:x:0:0:", analysis)

    def test_analyze_response_low_score_returns_none(self):
        test = make_test(hhs.URLParameterTest, FakeSession())
        self.assertIsNone(test.analyze_response(FakeResponse(text="permission denied")))


class CachePoisoningTests(unittest.TestCase):
    def test_url_with_buster_adds_cb_param(self):
        test = make_test(hhs.CachePoisoningTest, FakeSession(),
                         target="http://example.com/page?a=1")
        url = test._url_with_buster("xyz")
        self.assertIn("cb=xyz", url)
        self.assertIn("a=1", url)

    def test_worker_confirms_poisoning(self):
        # The worker uses uuid.uuid4().hex[:12] as the token; both request and
        # re-request bodies must carry that full token to confirm poisoning.
        session = FakeSession(responses=[
            FakeResponse(text="reflected TOKENTOKEN00 here"),   # poison request
            FakeResponse(text="still TOKENTOKEN00 cached"),      # confirm request
        ])
        test = make_test(hhs.CachePoisoningTest, session)

        import uuid
        original = uuid.uuid4

        class Fixed:
            hex = "TOKENTOKEN00"

        uuid.uuid4 = lambda: Fixed()
        try:
            test.worker("X-Forwarded-Host")
        finally:
            uuid.uuid4 = original
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertEqual(test.vulnerabilities_found[0]["test_result"], "Vulnerable")


class AuthBypassTests(unittest.TestCase):
    def test_worker_records_status_improvement(self):
        test = make_test(hhs.AuthBypassTest, FakeSession())
        test.baseline_status = 403
        test.baseline_len = 10
        test.request = lambda *a, **k: FakeResponse(status_code=200, text="secret")
        test.worker("host", "X-Forwarded-Host", "localhost")
        self.assertEqual(len(test.vulnerabilities_found), 1)
        self.assertEqual(test.vulnerabilities_found[0]["test_result"], "Vulnerable")

    def test_worker_ignores_when_no_improvement(self):
        test = make_test(hhs.AuthBypassTest, FakeSession())
        test.baseline_status = 403
        test.baseline_len = 10
        test.request = lambda *a, **k: FakeResponse(status_code=403)
        test.worker("host", "Host", "localhost")
        self.assertEqual(test.vulnerabilities_found, [])


class VhostDiscoveryTests(unittest.TestCase):
    def test_title_extraction(self):
        self.assertEqual(hhs.VhostDiscoveryTest._title("<title> Admin </title>"), "Admin")

    def test_title_missing_returns_empty(self):
        self.assertEqual(hhs.VhostDiscoveryTest._title("<h1>no title</h1>"), "")

    def test_candidate_hosts_shapes(self):
        test = make_test(hhs.VhostDiscoveryTest, FakeSession())
        hosts = test.candidate_hosts("admin")
        self.assertIn("admin", hosts)
        self.assertIn("admin.example.com", hosts)
        self.assertIn("admin.internal", hosts)


if __name__ == "__main__":
    unittest.main()
