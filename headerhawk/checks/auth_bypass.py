"""Host/forwarding-based access-control bypasses."""

from urllib.parse import urlparse

from .base import BaseTest
from .wordlists import PATH_OVERRIDE_HEADERS

class AuthBypassTest(BaseTest):
    """Detect Host/forwarding-based access-control bypasses.

    If the target responds 401/403, retry it presenting an internal/trusted
    host or client IP; a transition to 200 (or a materially different body)
    signals a bypass. Also probes front-end path-override headers
    (X-Original-URL / X-Rewrite-URL) used to reach restricted endpoints.
    """

    test_type = "Auth Bypass"

    INTERNAL_VALUES = {
        "Host": ["localhost", "127.0.0.1"],
        "X-Forwarded-Host": ["localhost", "127.0.0.1"],
        "X-Forwarded-For": ["127.0.0.1"],
        "X-Real-IP": ["127.0.0.1"],
        "True-Client-IP": ["127.0.0.1"],
        "X-Forwarded-Server": ["localhost"],
    }

    def run(self):
        baseline = self.request("GET", allow_redirects=False)
        if baseline is None:
            self.skip("the target did not answer the baseline request")
            return
        self.baseline_status = baseline.status_code
        self.baseline_len = len(baseline.content)

        cases = []
        if baseline.status_code in (401, 403):
            for header, values in self.INTERNAL_VALUES.items():
                for value in values:
                    cases.append(("host", header, value))
        for header in PATH_OVERRIDE_HEADERS:
            cases.append(("path", header, urlparse(self.target_url).path or "/"))
        self.run_pool(self.worker, cases, "Auth Bypass Testing")

    def worker(self, mode, header_name, value):
        request_url = self.target_url
        if mode == "path":
            # Request the site root but ask the front-end to route to the path.
            parsed = urlparse(self.target_url)
            request_url = parsed._replace(path="/", query="").geturl()
        response = self.request("GET", url=request_url,
                                headers={header_name: value},
                                allow_redirects=False)
        if response is None:
            return

        improved = (
            self.baseline_status in (401, 403)
            and response.status_code == 200
        )
        if not improved:
            return
        self.record({
            "url": request_url,
            "method": "GET",
            "header_name": header_name,
            "payload": value,
            "status_code": response.status_code,
            "analysis": (
                f"Access control bypass: baseline returned "
                f"{self.baseline_status}, but '{header_name}: {value}' "
                f"returned {response.status_code}."
            ),
            "test_result": "Vulnerable",
        })
