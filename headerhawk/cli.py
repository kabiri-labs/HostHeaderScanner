"""Command-line entry point: argument parsing and scan orchestration."""

import argparse
import sys
from urllib.parse import urlparse

from colorama import Fore, Style, init

from ._meta import __github_url__, __tool_name__, __version__
from .checks.registry import CHECKS
from .core.exitcodes import EXIT_ERROR, determine_exit_code
from .core.findings import DEFAULT_FAIL_ON, FAIL_ON_CLASSES, gated_finding_count
from .core.oob import OOBManager, confirm_oob_interactions
from .core.output import is_quiet, print_summary, resolve_quiet, set_quiet, status
from .core.ratelimit import RateLimiter
from .core.session import build_session
from .core.stats import RequestStats
from .report.evidence import save_evidence
from .report.writer import save_results


def parse_headers(raw_headers):
    headers = {}
    for item in raw_headers or []:
        if ":" not in item:
            continue
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="headerhawk",
        description="HeaderHawk - scan HTTP request headers for injection, "
                    "SSRF, cache poisoning and access-control bypass bugs.")
    parser.add_argument("url", nargs="?",
                        help="Target URL (omit when using --list)")
    parser.add_argument("--list", "-l", dest="list",
                        help="File of target URLs to scan, one per line "
                             "(blank lines and '#' comments are ignored)")
    parser.add_argument("--oob", help="OOB/collaborator domain for SSRF correlation")
    parser.add_argument("--oob-poll-url", dest="oob_poll_url",
                        help="Listener export URL polled afterwards to confirm OOB hits")
    parser.add_argument("--wordlist", "-w",
                        help="File of virtual-host names for discovery (one per line)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (1-20)")
    parser.add_argument("--rate", type=float, default=0.0,
                        help="Max requests per second across all threads "
                             "(0 = unlimited; use a low value to avoid WAF/rate blocks)")
    parser.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds")
    parser.add_argument("--methods", default="GET",
                        help="Comma-separated HTTP methods (e.g. GET,POST)")
    parser.add_argument("--header", "-H", action="append", dest="headers",
                        help="Extra request header 'Name: Value' (repeatable)")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--insecure", "-k", action="store_true",
                        help="Disable TLS certificate verification")
    parser.add_argument("--verbose", type=int, choices=[1, 2], default=1,
                        help="Verbosity level")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress progress bars and status output "
                             "(auto-enabled when stdout is not a TTY)")
    parser.add_argument("--enable-desync", dest="enable_desync",
                        action="store_true",
                        help="Confirm a suspected request-smuggling desync by "
                             "planting a smuggled prefix and checking whether a "
                             "following request is affected. INTRUSIVE: the "
                             "prefix can attach to another user's request and "
                             "corrupt or misroute live traffic. Without it, "
                             "smuggling is reported from timing alone")
    parser.add_argument("--fail-on", dest="fail_on",
                        choices=sorted(FAIL_ON_CLASSES), default=DEFAULT_FAIL_ON,
                        help="Which findings make the process exit 1: "
                             "'vuln' (default) counts proven vulnerabilities, "
                             "'posture' counts missing response-header controls, "
                             "'any' counts both, 'none' never fails on findings")
    parser.add_argument("--output", "-o",
                        help="Output file (.json, .sarif or .md)")
    parser.add_argument("--evidence",
                        help="Write a per-control compliance evidence "
                             "report to this path (.md or .json). Every "
                             "catalogued requirement is reported as Pass, "
                             "Fail or Not assessed, with the reason")
    args = parser.parse_args()
    if not 1 <= args.threads <= 20:
        parser.error("The --threads argument must be between 1 and 20.")
    if args.rate < 0:
        parser.error("The --rate argument must be 0 (unlimited) or positive.")
    if not args.url and not args.list:
        parser.error("Provide a target URL or --list <file>.")
    return args


def load_wordlist(path):
    if not path:
        return None
    try:
        with open(path) as handle:
            return [line.strip() for line in handle
                    if line.strip() and not line.startswith("#")]
    except OSError as exc:
        print(Fore.YELLOW + f"Could not read wordlist '{path}': {exc}. "
              "Using built-in list.")
        return None


def load_targets(args):
    """Resolve the target URLs from --list (a file) or the positional argument."""
    if args.list:
        targets = load_wordlist(args.list)
        if not targets:
            print(Fore.RED + f"No targets found in list file '{args.list}'.")
            sys.exit(EXIT_ERROR)
        return targets
    return [args.url]


def scan_target(url, args, session, methods, wordlist, stats, rate_limiter=None):
    """Run every test against a single URL and return the test objects.

    Returns None for an invalid URL so a batch run can skip it and continue.
    """
    hostname = urlparse(url).hostname
    if not hostname:
        print(Fore.YELLOW + f"Skipping invalid URL: {url}")
        return None

    oob_manager = OOBManager(args.oob, args.oob_poll_url) if args.oob else None
    status(f"\nTarget URL: {url}")
    status(f"Original Host: {hostname}")
    if oob_manager:
        status(f"OOB domain: {args.oob} (scan id {oob_manager.scan_id}).")

    common = dict(session=session, oob_domain=args.oob, methods=methods,
                  threads=args.threads, verbose=args.verbose, timeout=args.timeout,
                  oob_manager=oob_manager, wordlist=wordlist, insecure=args.insecure,
                  stats=stats, quiet=is_quiet(), rate_limiter=rate_limiter,
                  enable_desync=args.enable_desync)
    tests = [check(url, hostname, **common) for check in CHECKS]
    for test in tests:
        test.run()
    if oob_manager and oob_manager.poll_url:
        status("\nPolling OOB listener for interactions...")
        confirm_oob_interactions(oob_manager, session, args.timeout, tests)
    return tests


def main():
    args = parse_arguments()

    # Resolve quiet mode before anything is printed so status output, colour
    # stripping and progress bars all honour it consistently. When stdout is
    # redirected (a CI log, a file), colours and progress bars are noise.
    set_quiet(resolve_quiet(args.quiet, sys.stdout.isatty()))
    init(autoreset=True, strip=is_quiet() or None)

    status(Fore.CYAN + Style.BRIGHT + f"{__tool_name__} {__version__}")
    status(Fore.CYAN + f"GitHub: {__github_url__}\n")

    targets = load_targets(args)
    methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    extra_headers = parse_headers(args.headers)
    wordlist = load_wordlist(args.wordlist)

    rate_note = f"{args.rate:g} req/s" if args.rate > 0 else "unlimited"
    status(f"Targets: {len(targets)}")
    status(f"Methods: {', '.join(methods)}")
    status(f"Using {args.threads} threads (timeout {args.timeout}s, rate {rate_note}).")
    status(f"Verbosity level set to {args.verbose}.\n")

    session = build_session(
        timeout=args.timeout,
        threads=args.threads,
        insecure=args.insecure,
        proxy=args.proxy,
        extra_headers=extra_headers,
    )

    stats = RequestStats()
    rate_limiter = RateLimiter(args.rate)
    all_tests = []
    try:
        for url in targets:
            if len(targets) > 1:
                status(Fore.CYAN + Style.BRIGHT + f"\n===== Scanning {url} =====")
            tests = scan_target(url, args, session, methods, wordlist, stats,
                                rate_limiter=rate_limiter)
            if tests:
                all_tests.extend(tests)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Program interrupted by user.")
        save_results(args.output, all_tests, args.verbose)
        save_evidence(args.evidence, all_tests, targets, stats=stats,
                      version=__version__, tool_name=__tool_name__)
        sys.exit(EXIT_ERROR)

    if not all_tests:
        print(Fore.RED + "No valid targets were scanned.")
        return EXIT_ERROR

    save_results(args.output, all_tests, args.verbose)
    save_evidence(args.evidence, all_tests, targets, stats=stats,
                  version=__version__, tool_name=__tool_name__)
    print_summary(all_tests, targets, stats)
    # The exit code gates on the classes the caller asked for, so adding posture
    # checks does not turn an existing pipeline red on its own.
    return determine_exit_code(gated_finding_count(all_tests, args.fail_on), stats)
