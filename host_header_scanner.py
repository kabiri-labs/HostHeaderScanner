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

init(autoreset=True)

# Program metadata
__tool_name__ = "HostHeaderScanner"
__version__ = "1.2"
__github_url__ = "https://github.com/inpentest/HostHeaderScanner"

class BaseTest:
    def __init__(self, target_url, original_host, oob_domain=None, methods=None, threads=5, verbose=1):
        self.target_url = target_url
        self.original_host = original_host
        self.oob_domain = oob_domain
        self.methods = methods or ['GET', 'POST']
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

    def generate_payloads(self):
        internal_hosts = [
            'localhost', '127.0.0.1', '169.254.169.254',
            'metadata.google.internal', '192.168.1.1',
            'phpmyadmin', 'test'
        ]
        common_ports = [80, 443]
        payloads = internal_hosts + [f"{host}:{port}" for host in internal_hosts for port in common_ports]
        if self.oob_domain:
            payloads.append(self.oob_domain)
        return payloads

    def run(self):
        self.compute_typical_delay()  # Compute the typical delay time before starting the tests

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
                'payload': payload
            })
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
        threshold_multiplier = 2  # Adjust this value to balance false positives and negatives
        upper_threshold = mean_time + (stdev_time * threshold_multiplier)
        lower_threshold = mean_time - (stdev_time * threshold_multiplier)

        known_indicators = [
            'internal', 'localhost', 'phpmyadmin', 'database error',
            'root:x:', '127.0.0.1', 'server at', 'nginx', 'apache', 'sql syntax', 'fatal error'
        ]

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

            # Check for known indicators in response content
            lower_text = result['response_body'].lower()
            for indicator in known_indicators:
                if indicator in lower_text:
                    analysis += f"Response contains indicator: '{indicator}'. "
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
                    'analysis': analysis,
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
                    print(Fore.YELLOW + f"Analysis: {analysis}")
                    print(Fore.RED + "-" * 80)
            elif self.verbose == 2:
                self.all_results.append({
                    'test_type': 'SSRF',
                    'url': result['url'],
                    'method': result['method'],
                    'headers': result['headers'],
                    'header_name': result['header_name'],
                    'status_code': result['status_code'],
                    'response_time': response_time,
                    'analysis': "No significant anomalies detected.",
                    'test_result': 'Not Vulnerable'
                })

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

    def generate_payloads(self):
        payloads = [
            f"{self.oob_domain}" if self.oob_domain else 'example.com',
            'example.com',
            '//example.com',
            '/\\example.com',
            '/..//example.com',
            '///example.com',
            '////example.com/%2e%2e'
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
                if payload in location:
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


class URLParameterTest(BaseTest):
    def generate_payloads(self):
        payloads = []
        internal_urls = [
            'http://localhost', 'http://127.0.0.1', 'http://169.254.169.254',
            'http://metadata.google.internal', 'http://10.0.0.1', 'http://192.168.1.1',
            'http://172.16.0.1', 'file:///etc/passwd'
        ]
        if self.oob_domain:
            internal_urls.append(f'http://{self.oob_domain}')
        payloads.extend(internal_urls)
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        params_to_test = ['url', 'next', 'redirect', 'dest', 'destination', 'uri', 'path']
        test_cases = [
            (method, payload, param_name)
            for method in self.methods
            for payload in payloads
            for param_name in params_to_test
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

    def perform_request_wrapper(self, args):
        self.perform_request(*args)

    def perform_request(self, method, payload, param_name):
        common_headers = {
            'User-Agent': f'Mozilla/5.0 (compatible; {__tool_name__}/{__version__})',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        query_params[param_name] = payload
        new_query = urlencode(query_params, doseq=True)
        url_with_payload = parsed_url._replace(query=new_query).geturl()

        try:
            start_time = time.time()
            response = self.session.request(
                method, url_with_payload, headers=common_headers, timeout=5, allow_redirects=True
            )
            response_time = time.time() - start_time
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
            elif self.verbose == 2:
                self.all_results.append({
                    'test_type': 'URL Parameter SSRF',
                    'url': response.url,
                    'method': method,
                    'param_name': param_name,
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'analysis': "No significant anomalies detected.",
                    'test_result': 'Not Vulnerable'
                })
        except requests.RequestException:
            pass

    def analyze_response(self, response, payload):
        # Improved SSRF detection based on response content and redirection indicators
        known_indicators = [
            'root:x:', 'localhost', '127.0.0.1', 'metadata',
            'EC2', 'cloud', 'sql syntax', 'database error', 'exception', 'file not found',
            'error', 'not found', 'forbidden'
        ]
        lower_text = response.text.lower()
        analysis = ''
        for indicator in known_indicators:
            if indicator in lower_text:
                analysis += f"Response contains indicator: '{indicator}'. "
        if response.status_code in [301, 302, 303, 307, 308]:
            location_header = response.headers.get('Location', '')
            if payload in location_header:
                analysis += f"Redirects to payload URL: '{location_header}'. "
        return analysis if analysis else None

def parse_arguments():
    parser = argparse.ArgumentParser(description='Host Header Injection Testing Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--oob', help='OOB domain for testing')
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
    try:
        ssrf_test = SSRFTest(target_url, hostname, args.oob, threads=args.threads, verbose=args.verbose)
        ssrf_test.run()
        url_param_test = URLParameterTest(target_url, hostname, args.oob, threads=args.threads, verbose=args.verbose)
        url_param_test.run()
        open_redirect_test = OpenRedirectTest(target_url, hostname, args.oob, threads=args.threads, verbose=args.verbose)
        open_redirect_test.run()
        tests = [ssrf_test, url_param_test, open_redirect_test]
        save_results(args.output, tests, args.verbose)
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
