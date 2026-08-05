"""Shared test doubles for the HeaderHawk unit tests.

Everything here is fully offline: no sockets are opened and no real HTTP
requests are made. The doubles only expose the small surface the code under
test actually touches.
"""

class FakeElapsed:
    """Stand-in for ``response.elapsed`` exposing ``total_seconds()``."""

    def __init__(self, seconds):
        self._seconds = seconds

    def total_seconds(self):
        return self._seconds


class FakeResponse:
    """Minimal duck-type of ``requests.Response`` used across the tests."""

    def __init__(self, status_code=200, headers=None, text="", url="http://example.com/",
                 elapsed=0.0):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.text = text
        self.url = url
        self.content = text.encode("utf-8", "ignore")
        self.elapsed = FakeElapsed(elapsed)


class FakeSession:
    """Session double that records requests and returns queued responses.

    ``verify`` mirrors the attribute ``HostBypassTest`` inspects to decide the
    raw-client TLS verification mode.
    """

    def __init__(self, verify=True, responses=None):
        self.verify = verify
        self.headers = {}
        self.proxies = {}
        self.calls = []
        self._responses = list(responses or [])

    def request(self, method, url=None, headers=None, timeout=None,
                allow_redirects=True, data=None, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "headers": headers or {},
            "allow_redirects": allow_redirects,
            "data": data,
        })
        if not self._responses:
            raise AssertionError("FakeSession received an unexpected request")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def get(self, url, timeout=None):
        return self.request("GET", url=url)
