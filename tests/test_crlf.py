"""Tests for CRLF injection into response header fields.

The finding is only ever made on proof: a response header field named after this
scan's unique marker cannot have come from anywhere but the injected value. The
tests below pin that, and pin the two ways the check could become noisy - by
firing on a value merely echoed somewhere, or by reporting one hole once per
encoding that reaches it.
"""

import unittest

import headerhawk as hhs
from headerhawk.checks.crlf import (DECODED_REQUEST_HEADERS, REDIRECT_PARAMS,
                                    CRLFInjectionTest)
from tests.helpers import FakeResponse


class _ScriptedSession:
    """Answers according to a predicate over the request URL and headers."""

    def __init__(self, splits):
        self.verify = True
        self.headers = {}
        self.proxies = {}
        self.calls = []
        self._splits = splits

    def request(self, method, url=None, headers=None, timeout=None,
                allow_redirects=True, data=None, **kwargs):
        self.calls.append({"url": url, "headers": headers or {}})
        extra = self._splits(url or "", headers or {}) or {}
        return FakeResponse(status_code=302 if extra else 200,
                            headers=extra, url=url)


def _make(splits, url="http://t/"):
    test = CRLFInjectionTest(url, "t", session=_ScriptedSession(splits),
                             timeout=1, threads=1, verbose=0, quiet=True)
    return test


def _run(splits, url="http://t/"):
    test = _make(splits, url)
    test.run()
    return test


def _decoded_split(marker_source):
    """A server that URL-decodes the value and splices it into a header."""
    def splits(url, headers):
        import urllib.parse
        blob = marker_source(url, headers)
        if not blob:
            return None
        decoded = urllib.parse.unquote(blob)
        if "\r" not in decoded and "\n" not in decoded:
            return None
        # Everything after the break becomes a new header field.
        tail = decoded.replace("\r", "\n").split("\n")[-1]
        if ":" not in tail:
            return None
        name, _, value = tail.partition(":")
        return {name.strip(): value.strip()}
    return splits


class DetectionTests(unittest.TestCase):
    def test_a_marker_named_header_field_is_the_proof(self):
        test = _make(lambda url, headers: None)
        response = FakeResponse(headers={test.marker: "1"})
        self.assertEqual(test.injected_fields(response), [test.marker])

    def test_a_split_into_set_cookie_counts(self):
        test = _make(lambda url, headers: None)
        response = FakeResponse(headers={"Set-Cookie": f"a={test.token}"})
        self.assertEqual(test.injected_fields(response),
                         ["Set-Cookie (injected cookie)"])

    def test_the_marker_merely_echoed_in_a_value_is_not_a_finding(self):
        # Reflection is not injection; only a new header field proves the split.
        test = _make(lambda url, headers: None)
        response = FakeResponse(headers={"Location": f"https://x/{test.token}"})
        self.assertEqual(test.injected_fields(response), [])

    def test_an_ordinary_response_yields_nothing(self):
        test = _make(lambda url, headers: None)
        self.assertEqual(test.injected_fields(FakeResponse()), [])


class ParameterVectorTests(unittest.TestCase):
    def _next_param(self, url, headers):
        import urllib.parse
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        return query.get("next", [""])[0]

    def test_a_splittable_parameter_is_reported(self):
        found = _run(_decoded_split(self._next_param)).vulnerabilities_found
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["test_type"], CRLFInjectionTest.URL_BORNE)
        self.assertEqual(found[0]["param_name"], "next")
        self.assertEqual(found[0]["severity"], "High")

    def test_the_analysis_names_the_field_that_was_added(self):
        test = _run(_decoded_split(self._next_param))
        self.assertIn(test.marker, test.vulnerabilities_found[0]["analysis"])

    def test_one_hole_is_reported_once_not_once_per_encoding(self):
        # Several encodings reach the same parameter; that is one finding.
        test = _run(_decoded_split(self._next_param))
        subjects = [f.get("param_name") for f in test.vulnerabilities_found]
        self.assertEqual(subjects, ["next"])

    def test_every_redirect_parameter_is_tried(self):
        test = _run(lambda url, headers: None)
        tried = " ".join(call["url"] for call in test.session.calls)
        for param in REDIRECT_PARAMS:
            self.assertIn(f"{param}=", tried, param)


class PathVectorTests(unittest.TestCase):
    def test_a_splittable_path_is_reported(self):
        def path_value(url, headers):
            # Everything the probe appended after the target's own path.
            from urllib.parse import urlparse
            return urlparse(url).path.lstrip("/")

        found = _run(_decoded_split(path_value)).vulnerabilities_found
        self.assertTrue(found)
        self.assertEqual(found[0]["test_type"], CRLFInjectionTest.URL_BORNE)
        self.assertEqual(found[0]["param_name"], "(path)")


class HeaderVectorTests(unittest.TestCase):
    def test_a_splittable_request_header_is_reported(self):
        def from_header(url, headers):
            return headers.get("X-Forwarded-Host", "")

        found = _run(_decoded_split(from_header)).vulnerabilities_found
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["test_type"], CRLFInjectionTest.HEADER_BORNE)
        self.assertEqual(found[0]["header_name"], "X-Forwarded-Host")

    def test_every_candidate_header_is_tried(self):
        test = _run(lambda url, headers: None)
        sent = {name for call in test.session.calls for name in call["headers"]}
        for header in DECODED_REQUEST_HEADERS:
            self.assertIn(header, sent, header)

    def test_the_reproduction_carries_the_header(self):
        def from_header(url, headers):
            return headers.get("X-Forwarded-Host", "")

        found = _run(_decoded_split(from_header)).vulnerabilities_found
        self.assertIn("-H 'X-Forwarded-Host:", found[0]["repro"])


class QuietTargetTests(unittest.TestCase):
    def test_a_server_that_strips_control_characters_yields_nothing(self):
        def stripped(url, headers):
            return None  # nothing ever reaches a header field
        self.assertEqual(_run(stripped).vulnerabilities_found, [])

    def test_a_server_that_reflects_without_splitting_yields_nothing(self):
        def echoes(url, headers):
            return {"Location": "https://example.com/harmless"}
        self.assertEqual(_run(echoes).vulnerabilities_found, [])


class EncodingTests(unittest.TestCase):
    def test_the_encodings_cover_the_parsers_worth_covering(self):
        names = [name for name, _ in _make(lambda u, h: None).encodings()]
        self.assertIn("percent-encoded CRLF", names)
        self.assertIn("percent-encoded LF only", names)
        self.assertIn("double-encoded CRLF", names)
        self.assertIn("overlong UTF-8 CRLF", names)

    def test_every_payload_carries_the_scan_marker(self):
        test = _make(lambda u, h: None)
        for _, payload in test.encodings():
            self.assertIn(test.marker, payload)

    def test_the_marker_is_unique_per_scan(self):
        first = _make(lambda u, h: None)
        second = _make(lambda u, h: None)
        self.assertNotEqual(first.marker, second.marker)


class MappingTests(unittest.TestCase):
    def test_both_types_verify_the_output_encoding_requirement(self):
        for test_type in (CRLFInjectionTest.URL_BORNE,
                          CRLFInjectionTest.HEADER_BORNE):
            self.assertEqual(hhs.controls_for(test_type), ("ASVS-5.0:1.2.1",))

    def test_findings_are_vulnerability_class(self):
        def from_header(url, headers):
            return headers.get("X-Forwarded-Host", "")

        found = _run(_decoded_split(from_header)).vulnerabilities_found
        self.assertEqual(found[0]["finding_class"], hhs.CLASS_VULNERABILITY)


if __name__ == "__main__":
    unittest.main()
