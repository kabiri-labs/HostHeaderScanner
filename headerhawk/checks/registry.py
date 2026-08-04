"""Ordered registry of the active checks.

``scan_target`` instantiates these in order, so a new check is wired into the
scan by adding it here - the single place the CLI needs to learn about it.
"""

from .auth_bypass import AuthBypassTest
from .cache_poisoning import CachePoisoningTest
from .host_bypass import HostBypassTest
from .host_injection import HostInjectionTest
from .open_redirect import OpenRedirectTest
from .ssrf import SSRFTest
from .url_param import URLParameterTest
from .vhost import VhostDiscoveryTest

CHECKS = [
    HostInjectionTest,
    HostBypassTest,
    CachePoisoningTest,
    AuthBypassTest,
    VhostDiscoveryTest,
    SSRFTest,
    URLParameterTest,
    OpenRedirectTest,
]
