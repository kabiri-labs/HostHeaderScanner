"""Construction of the shared, connection-pooled requests session."""

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .._meta import __tool_name__, __version__

def build_session(timeout, threads, insecure, proxy, extra_headers):
    """Create a connection-pooled, retry-aware requests session."""
    session = requests.Session()
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
