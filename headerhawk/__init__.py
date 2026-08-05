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
from .checks.cors import CORSTest
from .checks.crlf import CRLFInjectionTest
from .checks.host_bypass import HostBypassTest
from .checks.host_injection import HostInjectionTest
from .checks.open_redirect import OpenRedirectTest
from .checks.registry import CHECKS, finding_types
from .checks.smuggling import RequestSmugglingTest
from .checks.ssrf import SSRFTest
from .checks.url_param import URLParameterTest
from .checks.vhost import VhostDiscoveryTest
from .checks.wordlists import (CACHE_STATUS_HEADERS, DEFAULT_VHOST_WORDLIST,
                               HOST_HEADERS, PATH_OVERRIDE_HEADERS,
                               UNKEYED_HOST_HEADERS)
from .cli import (load_targets, load_wordlist, main, parse_arguments,
                  parse_headers, scan_target)
from .compliance import (CONTROLS, CONTROLS_BY_TEST, STATUS_FAIL,
                         STATUS_NOT_ASSESSED, STATUS_PASS, Control,
                         ControlResult, build_evidence,
                         controls_covered_by, controls_for, describe,
                         summarise, unmapped_findings)
from .core.baseline import (collect_findings, compare, describe_drift,
                            finding_identity, load_baseline)
from .core.exitcodes import (EXIT_ERROR, EXIT_FINDINGS, EXIT_OK,
                             determine_exit_code)
from .core.findings import (CLASS_POSTURE, CLASS_VULNERABILITY,
                            count_by_class, finding_class_of,
                            gated_finding_count)
from .core.oob import OOBManager, confirm_oob_interactions
from .core.output import (is_quiet, print_summary, resolve_quiet, set_quiet,
                          status)
from .core.ratelimit import RateLimiter
from .core.session import build_session
from .core.severity import (DEFAULT_SEVERITY, SEVERITY_BY_TEST, SEVERITY_META,
                            severity_for)
from .core.stats import RequestStats
from .net.raw import RawHTTPClient, RawResponse, TimedResponse
from .posture import (RULES, Cookie, Issue, PostureRule, ResponseFacts,
                      ResponseHeaderPostureTest, parse_set_cookie,
                      set_cookie_values)
from .report.repro import build_reproduction
from .report.evidence import render_json, render_markdown, save_evidence
from .report.sarif import build_sarif
from .report.writer import save_results

init(autoreset=True)

__all__ = [
    "__github_url__", "__tool_name__", "__version__",
    "AuthBypassTest", "BaseTest", "CachePoisoningTest", "CORSTest", "CRLFInjectionTest",
    "HostBypassTest",
    "HostInjectionTest", "OpenRedirectTest", "SSRFTest", "URLParameterTest",
    "VhostDiscoveryTest", "RequestSmugglingTest", "CHECKS", "finding_types",
    "ResponseHeaderPostureTest", "PostureRule", "RULES", "Issue",
    "Cookie", "ResponseFacts", "parse_set_cookie", "set_cookie_values",
    "CLASS_POSTURE", "CLASS_VULNERABILITY", "count_by_class",
    "finding_class_of", "gated_finding_count",
    "CACHE_STATUS_HEADERS", "DEFAULT_VHOST_WORDLIST", "HOST_HEADERS",
    "PATH_OVERRIDE_HEADERS", "UNKEYED_HOST_HEADERS",
    "load_targets", "load_wordlist", "main", "parse_arguments",
    "parse_headers", "scan_target",
    "CONTROLS", "CONTROLS_BY_TEST", "Control", "ControlResult",
    "STATUS_FAIL", "STATUS_NOT_ASSESSED", "STATUS_PASS",
    "build_evidence", "controls_covered_by", "controls_for", "describe",
    "summarise", "unmapped_findings",
    "save_evidence", "render_markdown", "render_json",
    "EXIT_ERROR", "EXIT_FINDINGS", "EXIT_OK", "determine_exit_code",
    "collect_findings", "compare", "describe_drift", "finding_identity",
    "load_baseline",
    "OOBManager", "confirm_oob_interactions",
    "is_quiet", "print_summary", "resolve_quiet", "set_quiet", "status",
    "RateLimiter", "build_session", "RequestStats",
    "DEFAULT_SEVERITY", "SEVERITY_BY_TEST", "SEVERITY_META", "severity_for",
    "RawHTTPClient", "RawResponse", "TimedResponse",
    "build_reproduction", "build_sarif", "save_results",
]
