"""Tests for the CI-facing behaviour: quiet mode, request stats and exit codes."""

import contextlib
import io
import unittest
from unittest import mock

import requests

import headerhawk as hhs
from headerhawk.core import output as hh_output
from tests.helpers import FakeResponse, FakeSession


class ResolveQuietTests(unittest.TestCase):
    def test_flag_forces_quiet(self):
        self.assertTrue(hhs.resolve_quiet(True, stdout_isatty=True))

    def test_non_tty_implies_quiet(self):
        self.assertTrue(hhs.resolve_quiet(False, stdout_isatty=False))

    def test_interactive_without_flag_is_loud(self):
        self.assertFalse(hhs.resolve_quiet(False, stdout_isatty=True))


class StatusTests(unittest.TestCase):
    def _capture(self, quiet):
        buffer = io.StringIO()
        with mock.patch.object(hh_output, "_QUIET", quiet):
            with contextlib.redirect_stdout(buffer):
                hhs.status("hello")
        return buffer.getvalue()

    def test_prints_when_loud(self):
        self.assertEqual(self._capture(quiet=False), "hello\n")

    def test_silent_when_quiet(self):
        self.assertEqual(self._capture(quiet=True), "")


class RequestStatsTests(unittest.TestCase):
    def test_counts_success_and_failure(self):
        stats = hhs.RequestStats()
        stats.record(True)
        stats.record(False)
        stats.record(True)
        self.assertEqual(stats.total, 3)
        self.assertEqual(stats.failed, 1)
        self.assertEqual(stats.succeeded, 2)

    def test_all_failed_true_only_when_all_fail(self):
        stats = hhs.RequestStats()
        self.assertFalse(stats.all_failed)  # nothing attempted yet
        stats.record(False)
        stats.record(False)
        self.assertTrue(stats.all_failed)
        stats.record(True)
        self.assertFalse(stats.all_failed)


class DetermineExitCodeTests(unittest.TestCase):
    def test_clean_scan(self):
        stats = hhs.RequestStats()
        stats.record(True)
        self.assertEqual(hhs.determine_exit_code(0, stats), hhs.EXIT_OK)

    def test_findings_present(self):
        stats = hhs.RequestStats()
        stats.record(True)
        self.assertEqual(hhs.determine_exit_code(2, stats), hhs.EXIT_FINDINGS)

    def test_all_requests_failed_is_error(self):
        stats = hhs.RequestStats()
        stats.record(False)
        # Even with zero findings, an unreachable target is an error, not "clean".
        self.assertEqual(hhs.determine_exit_code(0, stats), hhs.EXIT_ERROR)

    def test_none_stats_falls_back_to_findings(self):
        self.assertEqual(hhs.determine_exit_code(0, None), hhs.EXIT_OK)
        self.assertEqual(hhs.determine_exit_code(1, None), hhs.EXIT_FINDINGS)


class RequestRecordsStatsTests(unittest.TestCase):
    def _make(self, session, stats):
        return hhs.HostInjectionTest("http://example.com/", "example.com",
                                     session=session, stats=stats, timeout=1)

    def test_success_recorded(self):
        stats = hhs.RequestStats()
        test = self._make(FakeSession(responses=[FakeResponse()]), stats)
        self.assertIsNotNone(test.request("GET"))
        self.assertEqual((stats.total, stats.failed), (1, 0))

    def test_failure_recorded(self):
        stats = hhs.RequestStats()
        session = FakeSession(responses=[requests.RequestException("down")])
        test = self._make(session, stats)
        self.assertIsNone(test.request("GET"))
        self.assertEqual((stats.total, stats.failed), (1, 1))


class QuietArgumentTests(unittest.TestCase):
    def test_quiet_flag_parsed(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--quiet"]):
            args = hhs.parse_arguments()
        self.assertTrue(args.quiet)

    def test_quiet_defaults_false(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            args = hhs.parse_arguments()
        self.assertFalse(args.quiet)


class RunPoolQuietTests(unittest.TestCase):
    def test_quiet_suppresses_starting_line(self):
        test = hhs.OpenRedirectTest("http://example.com/", "example.com",
                                    session=FakeSession(), quiet=True, threads=1)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            test.run_pool(lambda x: None, [(1,)], "Demo")
        self.assertNotIn("Starting Demo", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
