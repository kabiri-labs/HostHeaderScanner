"""Host-header driven open redirects."""

from urllib.parse import urlparse

from .base import BaseTest

class OpenRedirectTest(BaseTest):
    """Detect Host-header driven open redirects via the Location header."""

    test_type = "Open Redirect"
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    def generate_payloads(self):
        payloads = ["example.com", "www.example.com", "example.com:80",
                    "www.example.com:443"]
        if self.oob_manager:
            payloads.insert(0, self.oob_manager.host("redirect"))
        elif self.oob_domain:
            payloads.insert(0, self.oob_domain.strip("/"))
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        test_cases = [
            (method, "Host", payload)
            for method in self.methods
            for payload in payloads
        ]
        self.run_pool(self.worker, test_cases, "Open Redirect Testing")

    def worker(self, method, header_name, payload):
        response = self.request(method, headers={header_name: payload},
                                allow_redirects=False)
        if response is None or response.status_code not in self.REDIRECT_CODES:
            return
        location = response.headers.get("Location", "")
        injected_host = urlparse(f"http://{payload}").hostname
        response_host = urlparse(location).hostname
        if response_host and injected_host and response_host.lower() == injected_host.lower():
            self.record({
                "url": response.url,
                "method": method,
                "headers": {header_name: payload},
                "header_name": header_name,
                "payload": payload,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "analysis": f"Redirect to injected host via 'Location': {location}",
            })
