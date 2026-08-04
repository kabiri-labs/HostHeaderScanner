"""Tests for the per-control compliance evidence report.

The property the whole report rests on: a control is reported as passing only
when a check that covers it actually completed. A scan that reached nothing
produces no findings, and reporting that as full compliance would be worse than
producing no report at all.
"""

import json
import os
import tempfile
import unittest

import requests

import headerhawk as hhs
from headerhawk.compliance.evidence import (STATUS_FAIL, STATUS_NOT_ASSESSED,
                                            STATUS_PASS, build_evidence,
                                            controls_covered_by,
                                            unmapped_findings)
from headerhawk.report.evidence import render_json, render_markdown, save_evidence
from tests.helpers import FakeResponse, FakeSession


class _Check:
    """Stand-in for a check that has already run."""

    def __init__(self, test_type, emits, assessed=True, findings=(),
                 skip_reason=None):
        self.test_type = test_type
        self._emits = tuple(emits)
        self.assessed = assessed
        self.skip_reason = skip_reason
        self.vulnerabilities_found = list(findings)

    def emitted_types(self):
        return self._emits


def _finding(test_type, controls, severity="High"):
    return {"test_type": test_type, "controls": list(controls),
            "severity": severity, "url": "https://t/", "analysis": "because",
            "header_name": "Host", "repro": "curl ..."}


def _status_of(evidence, control_id):
    return next(r.status for r in evidence["controls"]
                if r.control.id == control_id)


def _result_for(evidence, control_id):
    return next(r for r in evidence["controls"] if r.control.id == control_id)


class StatusTests(unittest.TestCase):
    def test_a_completed_check_with_no_finding_passes(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True)]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:3.7.2"), STATUS_PASS)

    def test_a_finding_fails_the_control(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True,
                         findings=[_finding("Open Redirect", ["ASVS-5.0:3.7.2"])])]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:3.7.2"), STATUS_FAIL)

    def test_a_blocked_check_leaves_its_controls_unassessed(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=False,
                         skip_reason="the target did not answer")]
        evidence = build_evidence(checks, ["https://t/"])
        result = _result_for(evidence, "ASVS-5.0:3.7.2")
        self.assertEqual(result.status, STATUS_NOT_ASSESSED)
        self.assertEqual(result.not_assessed_because,
                         ["Open Redirect: the target did not answer"])

    def test_a_control_no_check_covers_is_unassessed(self):
        evidence = build_evidence([], ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:3.7.2"),
                         STATUS_NOT_ASSESSED)

    def test_every_catalogued_control_appears(self):
        # An assessor needs to see the gaps, not only the answers.
        evidence = build_evidence([], ["https://t/"])
        self.assertEqual({r.control.id for r in evidence["controls"]},
                         set(hhs.CONTROLS))

    def test_a_finding_beats_another_checks_failure_to_run(self):
        # 4.1.3 is covered by several checks. Evidence of a real failure stands
        # on its own even when a sibling check could not run.
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True,
                   findings=[_finding("Host Header Injection",
                                      ["ASVS-5.0:4.1.3"])]),
            _Check("Auth Bypass", ["Auth Bypass"], assessed=False,
                   skip_reason="no baseline"),
        ]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:4.1.3"), STATUS_FAIL)

    def test_one_completed_check_is_enough_to_pass_a_shared_control(self):
        checks = [
            _Check("Host Header Injection", ["Host Header Injection"],
                   assessed=True),
            _Check("Auth Bypass", ["Auth Bypass"], assessed=False,
                   skip_reason="no baseline"),
        ]
        evidence = build_evidence(checks, ["https://t/"])
        self.assertEqual(_status_of(evidence, "ASVS-5.0:4.1.3"), STATUS_PASS)


class UnreachableScanTests(unittest.TestCase):
    """The case that decides whether the report can be trusted at all."""

    def _blocked_evidence(self):
        checks = [_Check(name, emits, assessed=False,
                         skip_reason="no request to the target succeeded")
                  for name, emits in (("Open Redirect", ["Open Redirect"]),
                                      ("SSRF", ["SSRF"]))]
        return build_evidence(checks, ["https://t/"])

    def test_nothing_passes(self):
        evidence = self._blocked_evidence()
        self.assertEqual(evidence["counts"][STATUS_PASS], 0)
        self.assertEqual(evidence["counts"][STATUS_FAIL], 0)

    def test_everything_is_reported_as_not_assessed(self):
        evidence = self._blocked_evidence()
        self.assertEqual(evidence["counts"][STATUS_NOT_ASSESSED],
                         len(hhs.CONTROLS))

    def test_markdown_explains_why_that_is_not_compliance(self):
        body = render_markdown(self._blocked_evidence())
        self.assertIn("only reported as passing when a check that covers it "
                      "actually completed", body)


class CoverageMapTests(unittest.TestCase):
    def test_a_check_covers_the_controls_of_every_type_it_emits(self):
        covered = controls_covered_by(hhs.ResponseHeaderPostureTest)
        self.assertIn("ASVS-5.0:3.4.1", covered)   # HSTS
        self.assertIn("ASVS-5.0:3.3.4", covered)   # cookie HttpOnly
        self.assertIn("ASVS-5.0:13.4.6", covered)  # version disclosure

    def test_every_registered_check_covers_something_or_nothing_knowingly(self):
        # Not an assertion that every check maps - only that asking is safe.
        for check in hhs.CHECKS:
            self.assertIsInstance(controls_covered_by(check), set)


class AssessmentTrackingTests(unittest.TestCase):
    def test_a_check_that_answered_is_assessed(self):
        session = FakeSession(responses=[FakeResponse(url="https://t/")])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        self.assertTrue(test.assessed)
        self.assertIsNone(test.skip_reason)

    def test_a_check_whose_requests_all_failed_is_not_assessed(self):
        session = FakeSession(responses=[requests.RequestException()])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        self.assertFalse(test.assessed)
        self.assertEqual(test.skip_reason, "no request to the target succeeded")

    def test_a_check_that_skipped_reports_its_own_reason(self):
        session = FakeSession(responses=[FakeResponse(url="https://t/")] * 4)
        test = hhs.AuthBypassTest("https://t/", "t", session=session, timeout=1,
                                  verbose=0, quiet=True)
        test.skip("a made-up reason")
        self.assertFalse(test.assessed)
        self.assertEqual(test.skip_reason, "a made-up reason")


class UnmappedFindingTests(unittest.TestCase):
    def test_findings_outside_the_catalogue_are_collected(self):
        check = _Check("Permissions-Policy", ["Permissions-Policy"],
                       assessed=True,
                       findings=[_finding("Permissions-Policy", [])])
        self.assertEqual(len(unmapped_findings([check])), 1)

    def test_markdown_keeps_them_rather_than_dropping_them(self):
        check = _Check("Permissions-Policy", ["Permissions-Policy"],
                       assessed=True,
                       findings=[_finding("Permissions-Policy", [])])
        body = render_markdown(build_evidence([check], ["https://t/"]),
                               unmapped_findings([check]))
        self.assertIn("Findings Outside the Catalogue", body)


class RenderingTests(unittest.TestCase):
    def _evidence(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True,
                         findings=[_finding("Open Redirect",
                                            ["ASVS-5.0:3.7.2"])])]
        return build_evidence(checks, ["https://t/"], version="9.9.9",
                              tool_name="HeaderHawk")

    def test_markdown_carries_the_provenance_an_assessor_needs(self):
        body = render_markdown(self._evidence())
        self.assertIn("HeaderHawk 9.9.9", body)
        self.assertIn("**Generated:**", body)
        self.assertIn("https://t/", body)
        self.assertIn("ASVS-5.0:3.7.2 — FAIL", body)
        self.assertIn("https://github.com/OWASP/ASVS/", body)

    def test_json_is_machine_readable_and_ordered_worst_first(self):
        payload = json.loads(render_json(self._evidence()))
        self.assertEqual(payload["version"], "9.9.9")
        statuses = [c["status"] for c in payload["controls"]]
        self.assertEqual(statuses[0], STATUS_FAIL)
        failing = payload["controls"][0]
        self.assertEqual(failing["id"], "ASVS-5.0:3.7.2")
        self.assertEqual(len(failing["findings"]), 1)

    def test_save_evidence_picks_the_format_from_the_extension(self):
        checks = [_Check("Open Redirect", ["Open Redirect"], assessed=True)]
        with tempfile.TemporaryDirectory() as tmp:
            md = os.path.join(tmp, "e.md")
            js = os.path.join(tmp, "e.json")
            save_evidence(md, checks, ["https://t/"], version="1", tool_name="HH")
            save_evidence(js, checks, ["https://t/"], version="1", tool_name="HH")
            self.assertTrue(open(md).read().startswith("# HH Compliance Evidence"))
            json.loads(open(js).read())

    def test_no_path_writes_nothing(self):
        self.assertIsNone(save_evidence(None, [], []))


class PostureReproductionTests(unittest.TestCase):
    def test_a_posture_finding_reproduces_by_fetching_the_url(self):
        # header_name on a posture finding names what was assessed, not
        # something to send; echoing it back as a request header produced a
        # command that reproduced nothing.
        session = FakeSession(responses=[
            FakeResponse(headers={"Server": "nginx/1.18.0"}, url="https://t/")])
        test = hhs.ResponseHeaderPostureTest("https://t/", "t", session=session,
                                             timeout=1, verbose=0, quiet=True)
        test.run()
        for finding in test.vulnerabilities_found:
            self.assertNotIn("-H", finding["repro"], finding["test_type"])
            self.assertIn("https://t/", finding["repro"])

    def test_a_request_header_finding_still_shows_the_header(self):
        test = hhs.HostInjectionTest("http://t/", "t", session=None, timeout=1,
                                     verbose=0, quiet=True)
        test.record({"test_type": "Host Header Injection", "url": "http://t/",
                     "method": "GET", "header_name": "X-Forwarded-Host",
                     "payload": "evil", "status_code": 200, "analysis": "x"})
        self.assertIn("-H 'X-Forwarded-Host: evil'",
                      test.vulnerabilities_found[0]["repro"])


if __name__ == "__main__":
    unittest.main()
