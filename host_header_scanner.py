import argparse
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
import requests
from tqdm import tqdm
from multiprocessing.dummy import Pool as ThreadPool
import json
import statistics
from colorama import init, Fore, Style
import re  # Regular expressions for precise matching

init(autoreset=True)

# Program metadata
__tool_name__ = "HostHeaderScanner"
__version__ = "1.3"
__github_url__ = "https://github.com/inpentest/HostHeaderScanner"

class BaseTest:
    def __init__(self, target_url, original_host, oob_domain=None, methods=None, threads=5, verbose=1):
        self.target_url = target_url
        self.original_host = original_host
        self.oob_domain = oob_domain
        self.methods = methods or ['GET']
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        self.vulnerabilities_found = []
        self.all_results = []
        self.threads = threads
        self.verbose = verbose

    def run(self):
        raise NotImplementedError

class SSRFTest(BaseTest):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response_times = []
        self.results = []
        self.typical_delay = None
        self.baseline_headers = {}
        self.oob_interaction_detected = False  # Flag for OOB interaction
        self.excluded_headers = ['Date', 'Server', 'Content-Length', 'Connection', 'Vary']  # Headers to exclude from anomaly detection

    def compute_typical_delay(self):
        delays = []
        num_requests = 6  # Increased number of requests for better accuracy
        print("\nComputing typical delay time...")
        for i in range(num_requests):
            try:
                start_time = time.time()
                response = self.session.get(self.target_url, timeout=5)
                response_time = time.time() - start_time
                if i > 0:  # Exclude the first request
                    delays.append(response_time)
                    print(f"Request {i+1}: {response_time:.2f}s")
            except requests.RequestException:
                print(f"Request {i+1} failed.")
        if delays:
            # Optionally, remove the highest and lowest response times
            delays.sort()
            trimmed_delays = delays[1:-1] if len(delays) > 2 else delays
            self.typical_delay = sum(trimmed_delays) / len(trimmed_delays)
            print(f"\nTypical delay time calculated: {self.typical_delay:.2f}s")
        else:
            self.typical_delay = 1  # Default value if all requests failed
            print("\nFailed to compute typical delay time. Using default value of 1s.")

    def collect_baseline_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=5)
            self.baseline_headers = response.headers
            print("\nBaseline response headers collected for comparison.")
        except requests.RequestException:
            print("\nFailed to collect baseline headers.")
            self.baseline_headers = {}

    def generate_payloads(self):
        internal_hosts = [
            'localhost', '127.0.0.1', '169.254.169.254',
            'metadata.google.internal', '192.168.1.1',
            'phpmyadmin', 'test', '192.168.0.1',
            '10.0.0.1', '172.16.0.1', '10.0.0.2',
            '172.16.0.2', '192.168.1.100', '10.0.0.100',
            '172.16.0.100'
        ]
        common_ports = [80, 443]
        payloads = internal_hosts + [f"{host}:{port}" for host in internal_hosts for port in common_ports]
        if self.oob_domain:
            payloads.append(self.oob_domain)
        return payloads

    def run(self):
        self.compute_typical_delay()  # Compute the typical delay time before starting the tests
        self.collect_baseline_headers()  # Collect baseline headers

        payloads = self.generate_payloads()
        headers_to_test = [
            'Host', 'X-Forwarded-For', 'X-Forwarded-Host',
            'X-Real-IP', 'Forwarded'
        ]
        test_cases = [
            (method, {header_name: payload}, payload, header_name)
            for method in self.methods
            for payload in payloads
            for header_name in headers_to_test
        ]
        total_tests = len(test_cases)
        print("\nStarting SSRF Tests...")

        try:
            with tqdm(total=total_tests, desc="SSRF Testing", unit="test") as pbar:
                pool = ThreadPool(self.threads)
                for _ in pool.imap_unordered(self.perform_request_wrapper, test_cases):
                    pbar.update(1)
                pool.close()
                pool.join()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] SSRF Testing interrupted by user.")
            pool.terminate()
            pool.join()
            sys.exit(0)

        self.perform_statistical_analysis()

    def perform_request_wrapper(self, args):
        self.perform_request(*args)

    def perform_request(self, method, headers, payload, header_name):
        common_headers = {
            'User-Agent': f'Mozilla/5.0 (compatible; {__tool_name__}/{__version__})',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        request_headers = {**common_headers, **headers}
        try:
            start_time = time.time()
            response = self.session.request(
                method, self.target_url, headers=request_headers, timeout=5, allow_redirects=True
            )
            response_time = time.time() - start_time
            self.response_times.append(response_time)
            self.results.append({
                'url': response.url,
                'method': method,
                'headers': headers,
                'header_name': header_name,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_body': response.text[:1000],
                'response_headers': response.headers,
                'payload': payload
            })

            # Check for Out-of-Band (OOB) interactions
            if self.oob_domain and payload == self.oob_domain:
                # Monitor your OOB server separately to detect interactions
                # Here, you can implement logic to verify if an OOB request was received
                # For demonstration, we'll assume no interaction was detected
                pass

        except requests.RequestException:
            pass

    def perform_statistical_analysis(self):
        if not self.typical_delay:
            print(Fore.YELLOW + "Typical delay time not available for analysis.")
            return

        # Calculate mean and standard deviation
        mean_time = statistics.mean(self.response_times)
        stdev_time = statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0

        # Use dynamic threshold based on standard deviation
        threshold_multiplier = 2  # Adjusted to a reasonable value
        if stdev_time == 0:
            upper_threshold = mean_time * 1.5
            lower_threshold = mean_time * 0.5
        else:
            upper_threshold = mean_time + (stdev_time * threshold_multiplier)
            lower_threshold = max(mean_time - (stdev_time * threshold_multiplier), 0)

        known_indicators = [
            'localhost', 'phpmyadmin', 'database error',
            'root:x:0:0:', '127.0.0.1', 'server at', 'nginx', 'apache', 'sql syntax', 'fatal error'
        ]

        # Compile regex patterns for indicators with word boundaries
        indicator_patterns = {indicator: re.compile(r'\b' + re.escape(indicator) + r'\b') for indicator in known_indicators}

        for result in self.results:
            response_time = result['response_time']
            is_vulnerable = False
            analysis = ''

            # Check if response time is outside the acceptable range
            if response_time > upper_threshold:
                analysis += f"Response time ({response_time:.2f}s) exceeds upper threshold ({upper_threshold:.2f}s). "
                is_vulnerable = True
            elif response_time < lower_threshold:
                analysis += f"Response time ({response_time:.2f}s) is below lower threshold ({lower_threshold:.2f}s). "
                is_vulnerable = True

            # Check for known indicators in response content using regex
            lower_text = result['response_body'].lower()
            for indicator, pattern in indicator_patterns.items():
                if pattern.search(lower_text):
                    analysis += f"Response contains indicator: '{indicator}'. "
                    is_vulnerable = True

            # Check for response header anomalies, excluding specified headers
            if self.baseline_headers:
                response_headers = result.get('response_headers', {})
                header_anomalies = self.detect_header_anomalies(response_headers, self.baseline_headers)
                if header_anomalies:
                    analysis += f"Header anomalies detected: {header_anomalies}. "
                    is_vulnerable = True

            # Check if the response indicates an OOB interaction
            # Note: Actual OOB detection should be handled externally by monitoring your OOB server
            # Here, we provide a placeholder for future integration
            if self.oob_domain and self.payload_contains_oob(result['payload']):
                # Implement logic to verify OOB interaction
                # For example, ping your OOB server's API to check for received requests
                # Placeholder:
                oob_interaction = False  # Replace with actual check
                if oob_interaction:
                    analysis += "Out-of-Band interaction detected. "
                    is_vulnerable = True

            if is_vulnerable:
                test_result = 'Potentially Vulnerable'
                self.vulnerabilities_found.append({
                    'test_type': 'SSRF',
                    'url': result['url'],
                    'method': result['method'],
                    'headers': result['headers'],
                    'header_name': result['header_name'],
                    'payload': result['payload'],
                    'status_code': result['status_code'],
                    'response_time': response_time,
                    'analysis': analysis.strip(),
                    'test_result': test_result
                })
                if self.verbose >= 1:
                    print(Fore.RED + Style.BRIGHT + "\n[!] SSRF Potential Vulnerability Detected!")
                    print(f"URL: {result['url']}")
                    print(f"Method: {result['method']}")
                    print(f"Header: {result['header_name']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status Code: {result['status_code']}")
                    print(f"Response Time: {response_time:.2f}s")
                    print(Fore.YELLOW + f"Analysis: {analysis.strip()}")
                    print(Fore.RED + "-" * 80)
            elif self.verbose == 2:
                self.all_results.append({
                    'test_type': 'SSRF',
                    'url': result['url'],
                    'method': result['method'],
                    'headers': result['headers'],
                    'header_name': result['header_name'],
                    'payload': result['payload'],
                    'status_code': result['status_code'],
                    'response_time': response_time,
                    'analysis': "No significant anomalies detected.",
                    'test_result': 'Not Vulnerable'
                })

    def payload_contains_oob(self, payload):
        """
        Placeholder function to check if the payload contains the OOB domain.
        Implement actual logic based on your OOB server's setup.
        """
        return payload.strip('/') == self.oob_domain.strip('/') if self.oob_domain else False

    def detect_header_anomalies(self, response_headers, baseline_headers):
        """
        Compare response headers to baseline headers and identify anomalies.
        Excludes headers specified in self.excluded_headers.
        Returns a list of anomalies detected.
        """
        anomalies = []
        for header, value in response_headers.items():
            if header in self.excluded_headers:
                continue  # Skip excluded headers
            baseline_value = baseline_headers.get(header)
            if baseline_value:
                if value != baseline_value:
                    anomalies.append(f"{header} changed from '{baseline_value}' to '{value}'")
            else:
                anomalies.append(f"New header '{header}' added with value '{value}'")
        return anomalies

class OpenRedirectTest(BaseTest):
    def run(self):
        payloads = self.generate_payloads()
        headers_to_test = ['Host']
        test_cases = [
            (method, {header_name: payload}, payload, header_name)
            for method in self.methods
            for payload in payloads
            for header_name in headers_to_test
        ]
        total_tests = len(test_cases)
        print("\nStarting Open Redirect Tests...")

        try:
            with tqdm(total=total_tests, desc="Open Redirect Testing", unit="test") as pbar:
                pool = ThreadPool(self.threads)
                for _ in pool.imap_unordered(self.perform_request_wrapper, test_cases):
                    pbar.update(1)
                pool.close()
                pool.join()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Open Redirect Testing interrupted by user.")
            pool.terminate()
            pool.join()
            sys.exit(0)

        self.perform_redirect_analysis()

    def generate_payloads(self):
        payloads = [
            # Revised payloads without schemes and paths
            f"{self.oob_domain}" if self.oob_domain else 'example.com',
            'example.com',
            'www.example.com',
            'evil.com',
            'malicious.com',
            'attacker.com',
            'sub.example.com',
            'sub.attacker.com',
            '127.0.0.1',
            '192.168.1.1',
            '10.0.0.1',
            '[::1]',
            'localhost',
            'example.com:8080',
            'evil.com:443',
            'malicious.com:8000',
            'attacker.com:8080',
            'sub.example.com:3000',
            'sub.attacker.com:8443'
        ]
        return payloads

    def perform_request_wrapper(self, args):
        self.perform_request(*args)

    def perform_request(self, method, headers, payload, header_name):
        common_headers = {
            'User-Agent': f'Mozilla/5.0 (compatible; {__tool_name__}/{__version__})',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        request_headers = {**common_headers, **headers}

        try:
            response = self.session.request(
                method, self.target_url, headers=request_headers, timeout=5, allow_redirects=False
            )
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                # Check if the Location header starts with the injected host
                injected_host = urlparse(f"http://{payload}").hostname  # Extract hostname from payload
                parsed_location = urlparse(location)
                response_host = parsed_location.hostname
                if response_host and response_host.lower() == (injected_host or '').lower():
                    analysis = f"Redirection to injected host detected in 'Location' header: {location}"
                    self.vulnerabilities_found.append({
                        'test_type': 'Open Redirect',
                        'url': response.url,
                        'method': method,
                        'headers': headers,
                        'header_name': header_name,
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds(),
                        'analysis': analysis,
                        'test_result': 'Potentially Vulnerable'
                    })
                    if self.verbose >= 1:
                        print(Fore.RED + Style.BRIGHT + "\n[!] Open Redirect Vulnerability Detected!")
                        print(f"URL: {response.url}")
                        print(f"Method: {method}")
                        print(f"Header: {header_name}")
                        print(f"Payload: {payload}")
                        print(f"Status Code: {response.status_code}")
                        print(f"Location Header: {location}")
                        print(Fore.YELLOW + f"Analysis: {analysis}")
                        print(Fore.RED + "-" * 80)
        except requests.RequestException:
            pass

    def perform_redirect_analysis(self):
        # Additional analysis can be implemented here if needed
        pass

class URLParameterTest(BaseTest):
    def generate_payloads(self):
        payloads = []
        internal_urls = [
            '127.0.0.1',
            '169.254.169.254/latest/meta-data/',
            '/etc/passwd',
            '[::1]',  # IPv6 localhost
            '10.0.0.1',
            '10.0.0.2',
            '172.16.0.1',
            '172.31.255.255',
            '192.168.0.1',
            '192.168.255.255',
            '169.254.0.1',
            '169.254.255.254',
            '[fd00::]/',  # Unique local IPv6
            '///127.0.0.1',
            '////127.0.0.1',
            '127.0.0.1:80',
            '127.0.0.1:65535',
            '127.0.0.1:invalid',  # Invalid port
            '127.0.0.1:0',  # Edge port
            '127.0.0.1:99999',  # Out of range port
            '/%2e%2e',  # Path traversal
            '/etc/hosts',
            '/var/log/syslog',
            '/C:/Windows/System32/drivers/etc/hosts',
            # Encoded and obfuscated payloads
            'http%3A%2F%2F127.0.0.1',  # URL-encoded
            'http://127.0.0.1%2Fadmin',  # URL-encoded path
            'file%3A%2F%2F%2Fetc%2Fpasswd',  # URL-encoded file protocol
            'http://127.0.0.1\u200C',  # Zero-width non-joiner
            'http://\u0021@127.0.0.1',  # Unicode escape
        ]
        if self.oob_domain:
            # Ensure the OOB domain is properly formatted without schemes or paths
            # e.g., 'oob.example.com' instead of 'http://oob.example.com'
            oob_payload = self.oob_domain.strip('/')
            internal_urls.append(oob_payload)
        payloads.extend(internal_urls)
        return payloads

    def get_baseline_response(self):
        # Send a request with a benign parameter value
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        baseline_value = 'http://example.com'  # A benign URL
        for param in self.params_to_test:
            query_params[param] = baseline_value
        new_query = urlencode(query_params, doseq=True)
        url_with_baseline = parsed_url._replace(query=new_query).geturl()
        try:
            response = self.session.request(
                'GET', url_with_baseline, headers=self.common_headers, timeout=5, allow_redirects=True
            )
            return response
        except requests.RequestException:
            return None

    def run(self):
        self.common_headers = {
            'User-Agent': f'Mozilla/5.0 (compatible; {__tool_name__}/{__version__})',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        self.params_to_test = ['url', 'next', 'redirect', 'dest', 'destination', 'uri', 'path']
        self.baseline_response = self.get_baseline_response()
        payloads = self.generate_payloads()
        test_cases = [
            (method, payload, param_name)
            for method in self.methods
            for payload in payloads
            for param_name in self.params_to_test
        ]
        total_tests = len(test_cases)
        print("\nStarting URL Parameter SSRF Tests...")

        try:
            with tqdm(total=total_tests, desc="URL Parameter Testing", unit="test") as pbar:
                pool = ThreadPool(self.threads)
                for _ in pool.imap_unordered(self.perform_request_wrapper, test_cases):
                    pbar.update(1)
                pool.close()
                pool.join()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] URL Parameter Testing interrupted by user.")
            pool.terminate()
            pool.join()
            sys.exit(0)

        self.perform_parameter_analysis()

    def perform_request_wrapper(self, args):
        self.perform_request(*args)

    def perform_request(self, method, payload, param_name):
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        query_params[param_name] = payload
        new_query = urlencode(query_params, doseq=True)
        url_with_payload = parsed_url._replace(query=new_query).geturl()

        try:
            start_time = time.time()
            response = self.session.request(
                method, url_with_payload, headers=self.common_headers, timeout=5, allow_redirects=True
            )
            response_time = time.time() - start_time

            # Compare responses
            if self.baseline_response:
                is_different = self.is_response_different(self.baseline_response, response)
                if is_different:
                    analysis = self.analyze_response(response, payload)
                    if analysis:
                        self.vulnerabilities_found.append({
                            'test_type': 'URL Parameter SSRF',
                            'url': response.url,
                            'method': method,
                            'param_name': param_name,
                            'payload': payload,
                            'status_code': response.status_code,
                            'response_time': response_time,
                            'analysis': analysis,
                            'test_result': 'Potentially Vulnerable'
                        })
                        if self.verbose >= 1:
                            print(Fore.RED + Style.BRIGHT + "\n[!] URL Parameter SSRF Potential Vulnerability Detected!")
                            print(f"URL: {response.url}")
                            print(f"Method: {method}")
                            print(f"Parameter: {param_name}")
                            print(f"Payload: {payload}")
                            print(f"Status Code: {response.status_code}")
                            print(f"Response Time: {response_time:.2f}s")
                            print(Fore.YELLOW + f"Analysis: {analysis}")
                            print(Fore.RED + "-" * 80)
        except requests.RequestException:
            pass

    def perform_parameter_analysis(self):
        if not self.baseline_response:
            print(Fore.YELLOW + "Baseline response not available for parameter analysis.")
            return

        known_indicators = [
            'localhost', 'phpmyadmin', 'database error',
            'root:x:0:0:', '127.0.0.1', 'server at', 'nginx', 'apache', 'sql syntax', 'fatal error'
        ]

        # Compile regex patterns for indicators with word boundaries
        indicator_patterns = {indicator: re.compile(r'\b' + re.escape(indicator) + r'\b') for indicator in known_indicators}

        for result in self.vulnerabilities_found:
            # Additional analysis can be implemented here if needed
            pass

    def is_response_different(self, baseline_response, test_response):
        # Compare status codes
        if baseline_response.status_code != test_response.status_code:
            return True
        # Compare response lengths
        baseline_length = len(baseline_response.content)
        test_length = len(test_response.content)
        length_difference = abs(baseline_length - test_length)
        if length_difference > (0.1 * baseline_length):  # Allow 10% difference
            return True
        # Optionally compare specific headers
        return False

    def analyze_response(self, response, payload):
        lower_text = response.text.lower()
        score = 0
        analysis = ''
        # Assign weights
        indicators = {
            'root:x:0:0:': 5,
            '127.0.0.1': 3,
            'connection refused': 2,
            'permission denied': 2,
            'cannot open': 2,
            'failed to connect': 2,
            # Add more indicators as needed
        }
        for indicator, weight in indicators.items():
            if indicator in lower_text:
                score += weight
                analysis += f"Found indicator '{indicator}' (weight {weight}). "
        if response.status_code >= 500:
            score += 1
            analysis += f"Received server error status code: {response.status_code}. "
        # Define a threshold
        threshold = 5
        if score >= threshold:
            return analysis
        else:
            return None

def parse_arguments():
    parser = argparse.ArgumentParser(description='Host Header Injection Testing Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--oob', help='OOB domain for testing (e.g., oob.example.com)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (1-20)')
    parser.add_argument('--verbose', type=int, choices=[1, 2], default=1, help='Verbosity level')
    parser.add_argument('--output', '-o', help='Output file to save the test results')
    args = parser.parse_args()
    if not 1 <= args.threads <= 20:
        parser.error("The --threads argument must be between 1 and 20.")
    return args

def save_results(output_file, tests, verbose):
    if not output_file:
        return
    file_extension = output_file.split('.')[-1].lower()
    results = []
    for test in tests:
        if verbose == 2:
            results.extend(test.all_results)
        else:
            results.extend(test.vulnerabilities_found)
    if file_extension == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\nResults saved to {output_file}")
    else:
        lines = [
            "# Host Header Injection Testing Report",
            f"**Target URL:** {tests[0].target_url}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Vulnerabilities Found:** {len(results)}\n"
        ]
        if results:
            lines.append("## Test Results\n")
            for result in results:
                lines.extend([
                    f"### {result['test_type']} Test Result: {result['test_result']}",
                    f"- **URL:** {result['url']}",
                    f"- **Method:** {result['method']}",
                    f"- **Headers:** {result.get('headers', {})}",
                    f"- **Parameter:** {result.get('param_name', '')}",
                    f"- **Payload:** {result.get('payload', '')}",
                    f"- **Status Code:** {result['status_code']}",
                    f"- **Response Time:** {result['response_time']:.2f} seconds",
                    f"- **Analysis:** {result['analysis']}\n"
                ])
        else:
            lines.append("No vulnerabilities were found.\n")
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))
        print(f"\nReport saved to {output_file}")

def save_oob_logs(oob_logs):
    """
    Placeholder function to save OOB logs.
    Implement actual OOB log handling based on your OOB server setup.
    """
    pass

def main():
    print(Fore.CYAN + Style.BRIGHT + f"{__tool_name__} {__version__}")
    print(Fore.CYAN + f"GitHub: {__github_url__}\n")
    args = parse_arguments()
    target_url = args.url
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname
    if not hostname:
        print("Invalid URL provided.")
        sys.exit(1)
    print(f"Target URL: {target_url}")
    print(f"Original Host: {hostname}")
    print(f"Using {args.threads} threads.")
    print(f"Verbosity level set to {args.verbose}.")

    if args.oob:
        print(f"OOB Domain set to: {args.oob}")
        print("Ensure your OOB server is set up and monitoring for incoming requests.\n")
    else:
        print("No OOB Domain provided. OOB interaction monitoring will be disabled.\n")

    try:
        ssrf_test = SSRFTest(target_url, hostname, args.oob, methods=['GET'], threads=args.threads, verbose=args.verbose)
        ssrf_test.run()

        url_param_test = URLParameterTest(target_url, hostname, args.oob, methods=['GET'], threads=args.threads, verbose=args.verbose)
        url_param_test.run()

        open_redirect_test = OpenRedirectTest(target_url, hostname, args.oob, methods=['GET'], threads=args.threads, verbose=args.verbose)
        open_redirect_test.run()

        tests = [ssrf_test, url_param_test, open_redirect_test]
        save_results(args.output, tests, args.verbose)

        # Placeholder for OOB log saving if implemented
        # save_oob_logs(oob_logs)

        print(Fore.CYAN + Style.BRIGHT + "\n========== Test Summary ==========")
        total_vulns = sum(len(test.vulnerabilities_found) for test in tests)
        print(Fore.CYAN + f"Total vulnerabilities found: {total_vulns}")
        for test in tests:
            if test.vulnerabilities_found:
                test_name = test.__class__.__name__.replace('Test', '')
                print(Fore.MAGENTA + Style.BRIGHT + f"\n--- {test_name} Vulnerabilities ---")
                for vuln in test.vulnerabilities_found:
                    print(Fore.RED + f"- {vuln['method']} {vuln['url']}")
                    print(f"  Header/Parameter: {vuln.get('header_name') or vuln.get('param_name')}")
                    print(f"  Payload: {vuln['payload']}")
                    print(Fore.YELLOW + f"  Analysis: {vuln['analysis']}")
                    print(Fore.RED + "-" * 80)
        if total_vulns == 0:
            print(Fore.GREEN + "No vulnerabilities were found.")
        print(Fore.CYAN + "=" * 35)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Program interrupted by user.")
        sys.exit(0)

if __name__ == '__main__':
    main()
