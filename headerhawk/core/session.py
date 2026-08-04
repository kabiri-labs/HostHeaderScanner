"""Construction of the shared, connection-pooled requests session."""

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .._meta import __tool_name__, __version__


class _Session(requests.Session):
    """A session whose TLS-verification setting cannot be quietly overridden.

    ``requests`` consults ``REQUESTS_CA_BUNDLE`` and ``CURL_CA_BUNDLE`` whenever
    a request does not name ``verify`` itself, and the CA bundle it finds there
    wins over ``session.verify``. In an environment that sets either - a CI
    runner behind a TLS-inspecting proxy, a corporate image - that silently
    turns ``--insecure`` back off, and a scan of a host with a self-signed
    certificate fails every request while reporting the target as unreachable.

    Naming ``verify`` explicitly stops the environment being consulted at all.
    It is only forced when verification is off, so a target that legitimately
    needs a custom CA bundle from the environment still gets one.
    """

    def request(self, *args, **kwargs):
        if self.verify is False:
            kwargs.setdefault("verify", False)
        return super().request(*args, **kwargs)


def build_session(timeout, threads, insecure, proxy, extra_headers):
    """Create a connection-pooled, retry-aware requests session."""
    session = _Session()
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=None,  # retry on every method
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=max(threads, 10),
        pool_maxsize=max(threads * 2, 20),
        max_retries=retry,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": f"Mozilla/5.0 (compatible; {__tool_name__}/{__version__})",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    })
    if extra_headers:
        session.headers.update(extra_headers)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    if insecure:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session.request_timeout = timeout
    return session
