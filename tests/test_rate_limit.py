"""Tests for global request rate limiting (WAF-friendly pacing)."""

import time
import unittest
from unittest import mock

import requests

import headerhawk as hhs
from tests.helpers import FakeResponse, FakeSession


class _CountingLimiter:
    """Rate-limiter double that records how many times acquire() was called."""

    def __init__(self):
        self.calls = 0

    def acquire(self):
        self.calls += 1


class RateLimiterConfigTests(unittest.TestCase):
    def test_interval_from_rate(self):
        self.assertAlmostEqual(hhs.RateLimiter(5).min_interval, 0.2)

    def test_zero_rate_disables(self):
        self.assertEqual(hhs.RateLimiter(0).min_interval, 0.0)

    def test_negative_rate_disables(self):
        self.assertEqual(hhs.RateLimiter(-3).min_interval, 0.0)

    def test_acquire_noop_when_disabled(self):
        # No sleep should happen when limiting is off.
        with mock.patch.object(hhs.time, "sleep") as sleeper:
            hhs.RateLimiter(0).acquire()
        sleeper.assert_not_called()


class RateLimiterPacingTests(unittest.TestCase):
    def test_successive_slots_are_spaced(self):
        limiter = hhs.RateLimiter(10)  # 0.1s interval
        sleeps = []
        with mock.patch.object(hhs.time, "monotonic", return_value=100.0), \
             mock.patch.object(hhs.time, "sleep", side_effect=sleeps.append):
            limiter.acquire()   # first slot: now, no wait
            limiter.acquire()   # second slot: +0.1
            limiter.acquire()   # third slot: +0.2
        # First call needs no wait; the next two wait one and two intervals.
        self.assertEqual(len(sleeps), 2)
        self.assertAlmostEqual(sleeps[0], 0.1)
        self.assertAlmostEqual(sleeps[1], 0.2)

    def test_real_pacing_is_not_faster_than_rate(self):
        limiter = hhs.RateLimiter(50)  # 0.02s interval
        start = time.monotonic()
        for _ in range(4):
            limiter.acquire()
        # 4 slots => at least 3 intervals of spacing (~0.06s); allow slack.
        self.assertGreaterEqual(time.monotonic() - start, 0.04)


class RequestAppliesLimiterTests(unittest.TestCase):
    def _make(self, session, limiter):
        return hhs.HostInjectionTest("http://t/", "t", session=session,
                                     rate_limiter=limiter, verbose=0)

    def test_acquire_called_on_success(self):
        limiter = _CountingLimiter()
        test = self._make(FakeSession(responses=[FakeResponse()]), limiter)
        test.request("GET")
        self.assertEqual(limiter.calls, 1)

    def test_acquire_called_even_on_failure(self):
        limiter = _CountingLimiter()
        session = FakeSession(responses=[requests.RequestException("x")])
        test = self._make(session, limiter)
        test.request("GET")
        self.assertEqual(limiter.calls, 1)


class RawClientAppliesLimiterTests(unittest.TestCase):
    def test_send_acquires_before_connecting(self):
        limiter = _CountingLimiter()
        client = hhs.RawHTTPClient(timeout=1, rate_limiter=limiter)

        from tests.test_raw_proxy import FakeSocket
        sock = FakeSocket([b"HTTP/1.1 200 OK\r\n\r\nbody", b""])
        with mock.patch.object(hhs.socket, "create_connection", return_value=sock):
            client.send("http", "t", 80, "GET / HTTP/1.1", ["Host: t"])
        self.assertEqual(limiter.calls, 1)


class HostBypassPassesLimiterTests(unittest.TestCase):
    def test_client_receives_limiter(self):
        limiter = hhs.RateLimiter(10)
        test = hhs.HostBypassTest("http://example.com/", "example.com",
                                  session=FakeSession(), rate_limiter=limiter,
                                  timeout=1)
        self.assertIs(test.client.rate_limiter, limiter)


class RateArgumentTests(unittest.TestCase):
    def test_rate_parsed(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--rate", "3"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.rate, 3.0)

    def test_rate_defaults_to_zero(self):
        with mock.patch("sys.argv", ["prog", "http://t/"]):
            args = hhs.parse_arguments()
        self.assertEqual(args.rate, 0.0)

    def test_negative_rate_rejected(self):
        with mock.patch("sys.argv", ["prog", "http://t/", "--rate", "-1"]):
            with self.assertRaises(SystemExit):
                hhs.parse_arguments()


if __name__ == "__main__":
    unittest.main()
