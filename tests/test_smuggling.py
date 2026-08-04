"""Tests for timing-based request-smuggling detection.

The properties that matter here are mostly about restraint. A slow target must
not be read as a desync, the destructive probe must not run against a target
that already answered the safer one, the confirmation that can disrupt other
users must not run unless it was asked for, and every finding must say out loud
that timing is not proof.
"""

import unittest
from unittest import mock

import headerhawk as hhs
from headerhawk.checks.smuggling import (CONFIRMED_NOTE, TIMING_CAVEAT,
                                         RequestSmugglingTest)
from headerhawk.net.raw import RawResponse, TimedResponse
from tests.helpers import FakeSession


def _ok(elapsed=0.1, status_code=200):
    return TimedResponse(RawResponse(status_code, [], "ok"), elapsed, False)


def _hang(elapsed=9.0):
    return TimedResponse(None, elapsed, True)


class _ScriptedClient:
    """Raw-client double that answers based on what the request contains."""

    def __init__(self, responder):
        self.rate_limiter = None
        self.sent = []
        self._responder = responder

    def send_raw(self, scheme, host, port, request, sni_host=None,
                 read_timeout=None):
        self.sent.append(request)
        return self._responder(request)


def _make(responder, enable_desync=False, url="http://example.com/"):
    test = RequestSmugglingTest(url, "example.com", session=FakeSession(),
                                timeout=2, verbose=0, quiet=True,
                                enable_desync=enable_desync)
    test.client = _ScriptedClient(responder)
    return test


def _is_cl_te(request):
    return "Content-Length: 4" in request and "Transfer-Encoding" in request


def _is_te_cl(request):
    return "Content-Length: 6" in request and "Transfer-Encoding" in request


def _well_formed(request):
    return "Transfer-Encoding" not in request


class ProbeShapeTests(unittest.TestCase):
    def setUp(self):
        self.test = _make(lambda request: _ok())

    def test_cl_te_probe_understates_its_body_length(self):
        probe = self.test._cl_te_probe()
        self.assertIn("Content-Length: 4", probe)
        self.assertIn("Transfer-Encoding: chunked", probe)
        body = probe.split("\r\n\r\n", 1)[1]
        # Content-Length covers "1\r\nA" only; the rest is what the back-end
        # never receives, which is what makes it wait.
        self.assertEqual(body, "1\r\nA\r\nX")
        self.assertGreater(len(body), 4)

    def test_te_cl_probe_overstates_its_body_length(self):
        probe = self.test._te_cl_probe()
        self.assertIn("Content-Length: 6", probe)
        body = probe.split("\r\n\r\n", 1)[1]
        self.assertEqual(body, "0\r\n\r\nX")
        # The front-end forwards the five bytes up to the terminating chunk,
        # one short of the Content-Length the back-end is waiting for.
        self.assertEqual(len("0\r\n\r\n"), 5)

    def test_requests_are_sent_byte_for_byte(self):
        # Nothing may be appended: a body that disagrees with its own
        # Content-Length is the entire point.
        probe = self.test._cl_te_probe()
        self.assertTrue(probe.endswith("1\r\nA\r\nX"))


class NoFindingTests(unittest.TestCase):
    def test_a_responsive_target_reports_nothing(self):
        test = _make(lambda request: _ok())
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])

    def test_an_unreachable_target_is_skipped(self):
        test = _make(lambda request: TimedResponse(None, 0.0, False))
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])
        # Baseline never established, so no probe should have been attempted.
        self.assertFalse(any(_is_cl_te(r) for r in test.client.sent))

    def test_a_single_slow_probe_is_not_enough(self):
        # One hiccup proves nothing; the second probe has to agree.
        state = {"hung": False}

        def responder(request):
            if _is_cl_te(request) and not state["hung"]:
                state["hung"] = True
                return _hang()
            return _ok()

        test = _make(responder)
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])

    def test_a_target_that_went_slow_is_not_a_desync(self):
        # Both probes hang, but so does the well-formed control taken straight
        # afterwards: the target simply became slow. Catching that is the whole
        # reason the control request exists, and it is the dominant source of
        # false positives in timing-based detection.
        state = {"probed": False}

        def responder(request):
            if not _well_formed(request):
                state["probed"] = True
                return _hang()
            return _hang() if state["probed"] else _ok(elapsed=0.1)

        test = _make(responder)
        test.run()
        self.assertEqual(test.vulnerabilities_found, [])


class ClTeTests(unittest.TestCase):
    def _run_cl_te(self, enable_desync=False, follow_up_status=200):
        def responder(request):
            if _is_cl_te(request):
                return _hang()
            if "0\r\n\r\nGET" in request:
                return _hang()
            return _ok(status_code=follow_up_status)

        test = _make(responder, enable_desync=enable_desync)
        test.run()
        return test

    def test_detected_from_two_hanging_probes(self):
        found = self._run_cl_te().vulnerabilities_found
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["test_type"], RequestSmugglingTest.CL_TE)
        self.assertEqual(found[0]["severity"], "High")

    def test_reported_as_potential_without_confirmation(self):
        finding = self._run_cl_te().vulnerabilities_found[0]
        self.assertEqual(finding["test_result"], "Potentially Vulnerable")

    def test_finding_states_that_timing_is_not_proof(self):
        finding = self._run_cl_te().vulnerabilities_found[0]
        self.assertEqual(finding["confirmation"], TIMING_CAVEAT)
        self.assertIn("not proof", finding["confirmation"])
        self.assertIn("--enable-desync", finding["confirmation"])
        self.assertIn("another user", finding["confirmation"])

    def test_te_cl_is_not_probed_once_cl_te_is_found(self):
        # The TE.CL timing probe disrupts other users on a CL.TE-vulnerable
        # target, so it must not run once CL.TE has answered.
        test = self._run_cl_te()
        self.assertFalse(any(_is_te_cl(request) for request in test.client.sent))

    def test_carries_the_smuggling_controls(self):
        finding = self._run_cl_te().vulnerabilities_found[0]
        self.assertEqual(finding["controls"],
                         ["ASVS-5.0:4.2.1", "ASVS-5.0:4.2.2"])

    def test_reproduction_is_wire_level_not_curl(self):
        finding = self._run_cl_te().vulnerabilities_found[0]
        self.assertIn("printf", finding["repro"])
        self.assertNotIn("curl", finding["repro"])


class TeClTests(unittest.TestCase):
    def test_probed_only_when_cl_te_comes_back_clean(self):
        def responder(request):
            if _is_te_cl(request):
                return _hang()
            return _ok()

        test = _make(responder)
        test.run()
        found = test.vulnerabilities_found
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["test_type"], RequestSmugglingTest.TE_CL)
        self.assertTrue(any(_is_cl_te(r) for r in test.client.sent))


class DesyncConfirmationTests(unittest.TestCase):
    def _responder(self, confirm):
        """CL.TE hangs; the follow-up differs only when confirm is True."""
        state = {"attacked": False}

        def responder(request):
            if "0\r\n\r\nGET /" in request:
                state["attacked"] = True
                return _hang()
            if _is_cl_te(request):
                return _hang()
            if state["attacked"] and confirm:
                state["attacked"] = False   # only the next request is affected
                return _ok(status_code=404)
            return _ok(status_code=200)

        return responder

    def test_not_attempted_unless_asked_for(self):
        test = _make(self._responder(confirm=True), enable_desync=False)
        test.run()
        self.assertFalse(any("0\r\n\r\nGET /" in r for r in test.client.sent))
        self.assertEqual(test.vulnerabilities_found[0]["confirmation"],
                         TIMING_CAVEAT)

    def test_confirmed_finding_is_marked_vulnerable(self):
        test = _make(self._responder(confirm=True), enable_desync=True)
        test.run()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["test_result"], "Vulnerable")
        self.assertEqual(finding["confirmation"], CONFIRMED_NOTE)

    def test_unconfirmed_finding_keeps_the_caveat(self):
        test = _make(self._responder(confirm=False), enable_desync=True)
        test.run()
        finding = test.vulnerabilities_found[0]
        self.assertEqual(finding["test_result"], "Potentially Vulnerable")
        self.assertEqual(finding["confirmation"], TIMING_CAVEAT)


class BaselineTests(unittest.TestCase):
    def test_threshold_is_well_clear_of_a_slow_baseline(self):
        test = _make(lambda request: _ok(elapsed=3.0))
        self.assertTrue(test.measure_baseline())
        self.assertEqual(test.baseline, 3.0)
        self.assertGreaterEqual(test.threshold, 12.0)

    def test_threshold_has_a_floor_for_a_fast_baseline(self):
        test = _make(lambda request: _ok(elapsed=0.01))
        test.measure_baseline()
        # Four times almost nothing is still almost nothing, so a fixed margin
        # keeps a fast site from tripping on ordinary jitter.
        self.assertGreaterEqual(test.threshold, 4.0)


class CliFlagTests(unittest.TestCase):
    def test_defaults_to_off(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            self.assertFalse(hhs.parse_arguments().enable_desync)

    def test_can_be_switched_on(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--enable-desync"]):
            self.assertTrue(hhs.parse_arguments().enable_desync)


class ReportRenderingTests(unittest.TestCase):
    def test_confirmation_reaches_the_markdown_report(self):
        import os
        import tempfile

        class _Stub:
            target_url = "http://t/"
            test_type = "HTTP Request Smuggling (CL.TE)"
            all_results = []
            vulnerabilities_found = [{
                "test_type": "HTTP Request Smuggling (CL.TE)",
                "test_result": "Potentially Vulnerable", "url": "http://t/",
                "method": "POST", "payload": "CL.TE", "status_code": "no response",
                "analysis": "hung", "confirmation": TIMING_CAVEAT, "repro": "",
            }]

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.md")
            hhs.save_results(path, [_Stub()], verbose=1)
            content = open(path).read()
        self.assertIn("- **Confirming this:**", content)
        self.assertIn("--enable-desync", content)


if __name__ == "__main__":
    unittest.main()
