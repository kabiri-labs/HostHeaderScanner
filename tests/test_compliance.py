"""Tests for the control catalogue, the finding mapping and how both render.

A compliance report is read as evidence, so these tests guard the properties
that make it trustworthy: control ids resolve to a catalogued requirement, every
finding type the scanner can emit has been considered, and an unmapped finding
is reported as unmapped rather than quietly dropped.
"""

import json
import os
import tempfile
import unittest

import headerhawk as hhs
from headerhawk.checks.registry import CHECKS
from headerhawk.compliance import catalogue, mapping


def _finding(test_type="Host Header Injection", **overrides):
    entry = {
        "test_type": test_type,
        "test_result": "Potentially Vulnerable",
        "url": "http://t/",
        "method": "GET",
        "header_name": "Host",
        "payload": "evil",
        "status_code": 200,
        "analysis": "reflected",
        "repro": "",
    }
    entry.update(overrides)
    return entry


class _StubTest:
    def __init__(self, target_url, vulnerabilities):
        self.target_url = target_url
        self.vulnerabilities_found = vulnerabilities
        self.all_results = []
        self.test_type = "Host Header Injection"


class CatalogueTests(unittest.TestCase):
    def test_every_control_is_self_consistent(self):
        for control_id, control in catalogue.CONTROLS.items():
            self.assertEqual(control_id, control.id)
            self.assertTrue(control.id.endswith(control.section), control.id)
            self.assertTrue(control.title.strip(), control.id)
            self.assertTrue(control.url.startswith("https://"), control.id)

    def test_describe_returns_none_for_unknown_id(self):
        self.assertIsNone(catalogue.describe("ASVS-5.0:99.9.9"))


class MappingTests(unittest.TestCase):
    def test_every_mapped_control_is_catalogued(self):
        # The module refuses to import otherwise; assert the invariant directly
        # so the reason is visible when someone edits the mapping.
        for test_type, control_ids in mapping.CONTROLS_BY_TEST.items():
            for control_id in control_ids:
                self.assertIn(control_id, catalogue.CONTROLS,
                              f"{test_type} -> {control_id}")

    def test_every_check_type_is_considered(self):
        # A new check must be given a mapping decision, even if that decision is
        # "no control applies" - it may not be forgotten about.
        for check in CHECKS:
            self.assertIn(check.test_type, mapping.CONTROLS_BY_TEST,
                          check.__name__)

    def test_oob_finding_type_is_mapped(self):
        # Blind SSRF findings are appended by the OOB path, not by a check.
        self.assertIn("Blind SSRF (OOB)", mapping.CONTROLS_BY_TEST)

    def test_unmapped_type_returns_empty(self):
        self.assertEqual(hhs.controls_for("Nonexistent Finding"), ())


class FindingAnnotationTests(unittest.TestCase):
    def test_record_attaches_controls(self):
        test = hhs.HostInjectionTest("http://t/", "t", session=None, timeout=1)
        test.record(_finding())
        self.assertEqual(test.vulnerabilities_found[0]["controls"],
                         ["ASVS-5.0:4.1.3"])

    def test_record_keeps_explicit_controls(self):
        test = hhs.HostInjectionTest("http://t/", "t", session=None, timeout=1)
        test.record(_finding(controls=["ASVS-5.0:8.3.1"]))
        self.assertEqual(test.vulnerabilities_found[0]["controls"],
                         ["ASVS-5.0:8.3.1"])


class SummariseTests(unittest.TestCase):
    def test_counts_findings_per_control(self):
        rows, unmapped = hhs.summarise([
            _finding("Host Header Injection"),
            _finding("Web Cache Poisoning"),   # shares 4.1.3
            _finding("Open Redirect"),
        ])
        counts = {row[0].id: row[1] for row in rows}
        self.assertEqual(counts["ASVS-5.0:4.1.3"], 2)
        self.assertEqual(counts["ASVS-5.0:3.7.2"], 1)
        self.assertEqual(unmapped, 0)

    def test_reports_unmapped_findings(self):
        rows, unmapped = hhs.summarise([_finding("Nonexistent Finding")])
        self.assertEqual(rows, [])
        self.assertEqual(unmapped, 1)

    def test_rows_are_ordered_by_control_id(self):
        rows, _ = hhs.summarise([
            _finding("SSRF"), _finding("Open Redirect"),
        ])
        ids = [row[0].id for row in rows]
        self.assertEqual(ids, sorted(ids))


class ReportRenderingTests(unittest.TestCase):
    def _write(self, findings, suffix):
        tests = [_StubTest("http://t/", findings)]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f"out.{suffix}")
            hhs.save_results(path, tests, verbose=1)
            with open(path) as handle:
                return handle.read()

    def test_json_carries_controls(self):
        data = json.loads(self._write([_finding()], "json"))
        self.assertEqual(data[0]["controls"], ["ASVS-5.0:4.1.3"])

    def test_markdown_has_coverage_table_and_per_finding_controls(self):
        content = self._write([_finding()], "md")
        self.assertIn("## Control Coverage", content)
        self.assertIn("| [ASVS-5.0:4.1.3](", content)
        self.assertIn("- **Controls:** [ASVS-5.0:4.1.3](", content)

    def test_markdown_names_unmapped_findings(self):
        content = self._write([_finding("Nonexistent Finding")], "md")
        self.assertIn("map to no catalogued control", content)
        self.assertIn("- **Controls:** none catalogued", content)

    def test_sarif_tags_and_help_carry_controls(self):
        data = json.loads(self._write([_finding()], "sarif"))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertIn("ASVS-5.0:4.1.3", rule["properties"]["tags"])
        self.assertIn("cannot be overridden by the end user", rule["help"]["text"])
        result = data["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["controls"], ["ASVS-5.0:4.1.3"])

    def test_sarif_omits_help_for_unmapped_rule(self):
        data = json.loads(self._write([_finding("Nonexistent Finding")], "sarif"))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertNotIn("help", rule)
        self.assertEqual(rule["properties"]["tags"], ["security"])


if __name__ == "__main__":
    unittest.main()
