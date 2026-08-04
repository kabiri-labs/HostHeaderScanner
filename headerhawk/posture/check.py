"""The response-header posture check.

Unlike the active checks, this one attacks nothing: it fetches the target once
and reports the browser security controls the response does not carry. Its
findings are posture-class, so they do not fail a build unless ``--fail-on``
asks them to.
"""

from urllib.parse import urlparse

from ..checks.base import BaseTest
from ..core.findings import CLASS_POSTURE
from .rules import RULES


class ResponseHeaderPostureTest(BaseTest):
    """Assess the security header posture of the target's response.

    Redirects are followed, because the headers that matter are the ones on the
    document a browser actually renders; the finding records the URL that was
    assessed, which may differ from the URL that was requested.
    """

    test_type = "Response Header Posture"
    finding_class = CLASS_POSTURE

    @classmethod
    def emitted_types(cls):
        # Findings are named after the control they assess, not after the check,
        # so each gets its own severity, control mapping and SARIF rule.
        return tuple(rule.test_type for rule in RULES)

    def run(self):
        response = self.request("GET")
        if response is None:
            return
        assessed_url = getattr(response, "url", None) or self.target_url
        scheme = (urlparse(assessed_url).scheme or "").lower()
        headers = {name.lower(): value
                   for name, value in dict(response.headers).items()}

        for rule in RULES:
            outcome = rule.assess(headers, scheme)
            if outcome is None:
                continue
            test_result, analysis = outcome
            self.record({
                "test_type": rule.test_type,
                "test_result": test_result,
                "severity": rule.severity,
                "url": assessed_url,
                "method": "GET",
                "header_name": rule.test_type,
                "payload": "",
                "status_code": response.status_code,
                "analysis": analysis,
            })
