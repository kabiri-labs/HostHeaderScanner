"""HeaderHawk - scan HTTP request headers for injection, SSRF, cache-poisoning and access-control bugs.

The implementation lives in focused submodules; this package root re-exports the
public surface so ``import headerhawk`` keeps working exactly as it did when the
whole tool was a single file.
"""

from colorama import init

from ._meta import __github_url__, __tool_name__, __version__
from .checks.auth_bypass import AuthBypassTest
from .checks.base import BaseTest
from .checks.cache_poisoning import CachePoisoningTest
from .checks.host_bypass import HostBypassTest
from .checks.host_injection import HostInjectionTest
from .checks.open_redirect import OpenRedirectTest
from .checks.registry import CHECKS
from .checks.ssrf import SSRFTest
from .checks.url_param import URLParameterTest
from .checks.vhost import VhostDiscoveryTest
from .checks.wordlists import (CACHE_STATUS_HEADERS, DEFAULT_VHOST_WORDLIST,
                               HOST_HEADERS, PATH_OVERRIDE_HEADERS,
                               UNKEYED_HOST_HEADERS)
from .cli import (load_targets, load_wordlist, main, parse_arguments,
                  parse_headers, scan_target)
from .core.exitcodes import (EXIT_ERROR, EXIT_FINDINGS, EXIT_OK,
                             determine_exit_code)
from .core.oob import OOBManager, confirm_oob_interactions
from .core.output import (is_quiet, print_summary, resolve_quiet, set_quiet,
                          status)
from .core.ratelimit import RateLimiter
from .core.session import build_session
from .core.severity import (DEFAULT_SEVERITY, SEVERITY_BY_TEST, SEVERITY_META,
                            severity_for)
from .core.stats import RequestStats
from .net.raw import RawHTTPClient, RawResponse
from .report.repro import build_reproduction
from .report.sarif import build_sarif
from .report.writer import save_results

init(autoreset=True)

__all__ = [
    "__github_url__", "__tool_name__", "__version__",
    "AuthBypassTest", "BaseTest", "CachePoisoningTest", "HostBypassTest",
    "HostInjectionTest", "OpenRedirectTest", "SSRFTest", "URLParameterTest",
    "VhostDiscoveryTest", "CHECKS",
    "CACHE_STATUS_HEADERS", "DEFAULT_VHOST_WORDLIST", "HOST_HEADERS",
    "PATH_OVERRIDE_HEADERS", "UNKEYED_HOST_HEADERS",
    "load_targets", "load_wordlist", "main", "parse_arguments",
    "parse_headers", "scan_target",
    "EXIT_ERROR", "EXIT_FINDINGS", "EXIT_OK", "determine_exit_code",
    "OOBManager", "confirm_oob_interactions",
    "is_quiet", "print_summary", "resolve_quiet", "set_quiet", "status",
    "RateLimiter", "build_session", "RequestStats",
    "DEFAULT_SEVERITY", "SEVERITY_BY_TEST", "SEVERITY_META", "severity_for",
    "RawHTTPClient", "RawResponse",
    "build_reproduction", "build_sarif", "save_results",
]
