"""Shared scaffolding every check builds on."""

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from colorama import Fore, Style
from tqdm import tqdm

from ..compliance import controls_for
from ..core.findings import DEFAULT_FINDING_CLASS
from ..core.severity import severity_for
from ..report.repro import build_reproduction


class BaseTest:
    """Shared scaffolding for every test type."""

    test_type = "Base"
    # Findings default to the vulnerability class; posture checks override it.
    finding_class = DEFAULT_FINDING_CLASS

    @classmethod
    def emitted_types(cls):
        """Finding types this check can emit.

        Usually just its own, but a check that reports several distinct
        issues from one pass overrides this so the severity and compliance
        maps can be checked for completeness against it.
        """
        return (cls.test_type,)

    def __init__(self, target_url, original_host, session, oob_domain=None,
                 methods=None, threads=5, verbose=1, timeout=10,
                 oob_manager=None, wordlist=None, insecure=False,
                 stats=None, quiet=False, rate_limiter=None,
                 enable_desync=False):
        self.target_url = target_url
        self.original_host = original_host
        self.session = session
        self.oob_domain = oob_domain
        self.oob_manager = oob_manager
        self.wordlist = wordlist
        self.insecure = insecure
        self.methods = methods or ["GET"]
        self.threads = threads
        self.verbose = verbose
        self.timeout = timeout
        self.stats = stats
        self.quiet = quiet
        self.rate_limiter = rate_limiter
        # Only the desync check acts on this; it is accepted here so the CLI
        # can hand every check the same options.
        self.enable_desync = enable_desync
        self.vulnerabilities_found = []
        self.all_results = []

    def request(self, method, url=None, headers=None, allow_redirects=True):
        """Issue a single request, returning the response or None on failure."""
        if self.rate_limiter is not None:
            self.rate_limiter.acquire()
        try:
            response = self.session.request(
                method,
                url or self.target_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
            )
            if self.stats is not None:
                self.stats.record(True)
            return response
        except requests.RequestException as exc:
            if self.stats is not None:
                self.stats.record(
                    False, tls_error=isinstance(exc, requests.exceptions.SSLError))
            return None

    def run_pool(self, worker, test_cases, description):
        """Run worker over test_cases with a bounded thread pool and progress bar."""
        if not test_cases:
            return
        if not self.quiet:
            print(f"\nStarting {description}...")
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(worker, *case) for case in test_cases]
                with tqdm(total=len(futures), desc=description, unit="test",
                          disable=self.quiet) as pbar:
                    for future in as_completed(futures):
                        future.result()
                        pbar.update(1)
        except KeyboardInterrupt:
            print(Fore.YELLOW + f"\n[!] {description} interrupted by user.")
            raise

    def record(self, entry):
        """Store a confirmed/suspected finding and optionally print it."""
        entry.setdefault("test_type", self.test_type)
        entry.setdefault("test_result", "Potentially Vulnerable")
        entry.setdefault("severity", severity_for(entry["test_type"]))
        entry.setdefault("controls", list(controls_for(entry["test_type"])))
        entry.setdefault("finding_class", self.finding_class)
        entry["repro"] = build_reproduction(entry, self.target_url, self.insecure)
        self.vulnerabilities_found.append(entry)
        if self.verbose >= 1:
            self._print_finding(entry)

    def _print_finding(self, entry):
        print(Fore.RED + Style.BRIGHT +
              f"\n[!] {entry['test_type']} Finding! [{entry.get('severity', '')}]")
        print(f"URL: {entry.get('url')}")
        print(f"Method: {entry.get('method')}")
        if entry.get("header_name"):
            print(f"Header: {entry['header_name']}")
        if entry.get("param_name"):
            print(f"Parameter: {entry['param_name']}")
        print(f"Payload: {entry.get('payload')}")
        print(f"Status Code: {entry.get('status_code')}")
        if entry.get("response_time") is not None:
            print(f"Response Time: {entry['response_time']:.2f}s")
        print(Fore.YELLOW + f"Analysis: {entry.get('analysis')}")
        if entry.get("confirmation"):
            print(Fore.CYAN + f"Confirming this: {entry['confirmation']}")
        if entry.get("repro"):
            print(Fore.GREEN + f"Reproduce: {entry['repro']}")
        print(Fore.RED + "-" * 80)

    def run(self):
        raise NotImplementedError
