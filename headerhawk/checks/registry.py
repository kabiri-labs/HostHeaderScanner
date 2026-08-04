"""Ordered registry of the active checks.

``scan_target`` instantiates these in order, so a new check is wired into the
scan by adding it here - the single place the CLI needs to learn about it.
"""

from ..core.oob import OOB_TEST_TYPE
from ..posture import ResponseHeaderPostureTest
from .auth_bypass import AuthBypassTest
from .cache_poisoning import CachePoisoningTest
from .host_bypass import HostBypassTest
from .host_injection import HostInjectionTest
from .open_redirect import OpenRedirectTest
from .ssrf import SSRFTest
from .url_param import URLParameterTest
from .vhost import VhostDiscoveryTest

CHECKS = [
    # Posture runs first: it is a single request and it frames everything the
    # active checks go on to report.
    ResponseHeaderPostureTest,
    HostInjectionTest,
    HostBypassTest,
    CachePoisoningTest,
    AuthBypassTest,
    VhostDiscoveryTest,
    SSRFTest,
    URLParameterTest,
    OpenRedirectTest,
]


def finding_types():
    """Every finding type the scanner can emit, from any source.

    The severity and compliance maps are checked for completeness against this,
    so a check that reports several distinct issues cannot slip through with
    only its own name covered.
    """
    types = {OOB_TEST_TYPE}
    for check in CHECKS:
        types.update(check.emitted_types())
    return sorted(types)
