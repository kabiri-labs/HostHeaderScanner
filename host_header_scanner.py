import argparse
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests
from tqdm import tqdm
from multiprocessing.dummy import Pool as ThreadPool
import json
import statistics
from colorama import init, Fore, Style

init(autoreset=True)

# Program metadata
__tool_name__ = "HostHeaderScanner"
__version__ = "1.0"
__github_url__ = "https://github.com/inpentest/HostHeaderScanner"

class BaseTest:
    def __init__(self, target_url, original_host, oob_domain=None, methods=None, threads=5, verbose=1):
        self.target_url = target_url
        self.original_host = original_host
        self.oob_domain = oob_domain
        self.methods = methods or ['GET', 'POST', 'PUT', 'DELETE']
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

    def generate_payloads(self):
        internal_hosts = [
            'localhost', '127.0.0.1', '169.254.169.254',
            'metadata.google.internal', '10.0.0.1', '192.168.1.1',
            '172.16.0.1', 'phpmyadmin', 'api', 'mysql', 'www', 'nginx', 'php',
        ]
        common_ports = [80, 81, 8080, 3306]
        payloads = internal_hosts + [f"{host}:{port}" for host in internal_hosts for port in common_ports]
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        positions = [
            lambda p: p,
            lambda p: f"{self.original_host}&{p}",
            lambda p: f"{p}&{self.original_host}",
        ]
        test_cases = [
            (method, {'Host': position(payload)}, payload)
            for method in self.methods
            for payload in payloads
            for position in positions
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

    def perform_request(self, method, headers, payload):
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
                'status_code': response.status_code,
                'response_time': response_time,
                'response_body': response.text[:500],
                'payload': payload
            })
        except requests.RequestException:
            pass

    def perform_statistical_analysis(self):
        if len(self.response_times) < 2:
            print(Fore.YELLOW + "Not enough data to perform statistical analysis.")
            return
        mean_time = statistics.mean(self.response_times)
        stdev_time = statistics.stdev(self.response_times)
        threshold = 4
        for result in self.results:
            response_time = result['response_time']
            z_score = (response_time - mean_time) / stdev_time if stdev_time > 0 else 0
            if abs(z_score) >= threshold:
                test_result = 'Potentially Vulnerable'
                analysis = (
                    f"Response time ({response_time:.2f}s) is {abs(z_score):.2f} standard deviations "
                    f"{'faster' if z_score < 0 else 'slower'} than the mean ({mean_time:.2f}s)."
                )
                lower_text = result['response_body'].lower()
                if any(keyword in lower_text for keyword in ['internal', 'localhost', 'phpmyadmin', 'database error']):
                    analysis += " Response body contains indicators of internal server access."
                self.vulnerabilities_found.append({
                    'test_type': 'SSRF',
                    'url': result['url'],
                    'method': result['method'],
                    'headers': result['headers'],
                    'status_code': result['status_code'],
                    'response_time': response_time,
                    'analysis': analysis,
                    'test_result': test_result
                })
                print(Fore.RED + Style.BRIGHT + "\n[!] SSRF Potential Vulnerability Detected!")
                print(f"URL: {result['url']}")
                print(f"Method: {result['method']}")
                print(f"Headers: {result['headers']}")
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
                    'status_code': result['status_code'],
                    'response_time': response_time,
                    'analysis': f"Response time ({response_time:.2f}s) is within normal range.",
                    'test_result': 'Not Vulnerable'
                })

class OpenRedirectTest(BaseTest):
    def generate_payloads(self):
        payloads = ['example.com', 'example.net:443']
        if self.oob_domain:
            payloads.append(self.oob_domain)
        return payloads

    def run(self):
        payloads = self.generate_payloads()
        positions = [
            lambda p: p,
            lambda p: f"{p}&{self.original_host}",
            lambda p: f"{self.original_host}&{p}",
        ]
        test_cases = [
            (method, {'Host': position(payload)}, payload)
            for method in self.methods
            for payload in payloads
            for position in positions
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

    def perform_request_wrapper(self, args):
        self.perform_request(*args)

    def perform_request(self, method, headers, payload):
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
                method, self.target_url, headers=request_headers, timeout=5, allow_redirects=False
            )
            response_time = time.time() - start_time
            self.analyze_response(response, headers, method, response_time, payload)
        except requests.RequestException:
            pass

    def analyze_response(self, response, headers, method, response_time, payload):
        status_code = response.status_code
        if status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if not location:
                return
            redirect_url = urljoin(self.target_url, location)
            redirect_parsed = urlparse(redirect_url)
            redirect_host = redirect_parsed.hostname
            redirect_port = redirect_parsed.port
            payload_parsed = urlparse('//' + payload)
            payload_host = payload_parsed.hostname
            payload_port = payload_parsed.port or (443 if redirect_parsed.scheme == 'https' else 80)
            if redirect_host == payload_host and (redirect_port == payload_port or redirect_port is None):
                analysis = f"Redirected to {redirect_url} which matches the payload."
                self.vulnerabilities_found.append({
                    'test_type': 'Open Redirect',
                    'url': response.url,
                    'method': method,
                    'headers': headers,
                    'status_code': status_code,
                    'response_time': response_time,
                    'analysis': analysis,
                    'test_result': 'Vulnerable'
                })
                print(Fore.RED + Style.BRIGHT + "\n[!] Open Redirect Vulnerability Detected!")
                print(f"URL: {response.url}")
                print(f"Method: {method}")
                print(f"Headers: {headers}")
                print(f"Status Code: {status_code}")
                print(f"Response Time: {response_time:.2f}s")
                print(Fore.YELLOW + f"Analysis: {analysis}")
                print(Fore.RED + "-" * 80)
            elif self.verbose == 2:
                self.all_results.append({
                    'test_type': 'Open Redirect',
                    'url': response.url,
                    'method': method,
                    'headers': headers,
                    'status_code': status_code,
                    'response_time': response_time,
                    'analysis': f"Redirected to {redirect_url}, does not match payload.",
                    'test_result': 'Not Vulnerable'
                })
        elif self.verbose == 2:
            self.all_results.append({
                'test_type': 'Open Redirect',
                'url': response.url,
                'method': method,
                'headers': headers,
                'status_code': status_code,
                'response_time': response_time,
                'analysis': "No redirection occurred.",
                'test_result': 'Not Vulnerable'
            })

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

def save_results(output_file, ssrf_test, open_redirect_test, verbose):
    if not output_file:
        return
    file_extension = output_file.split('.')[-1].lower()
    results = ssrf_test.all_results + open_redirect_test.all_results if verbose == 2 else \
              ssrf_test.vulnerabilities_found + open_redirect_test.vulnerabilities_found
    if file_extension == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\nResults saved to {output_file}")
    else:
        lines = [
            "# Host Header Injection Testing Report",
            f"**Target URL:** {ssrf_test.target_url}",
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
                    f"- **Headers:** {result['headers']}",
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
        open_redirect_test = OpenRedirectTest(target_url, hostname, args.oob, threads=args.threads, verbose=args.verbose)
        open_redirect_test.run()
        save_results(args.output, ssrf_test, open_redirect_test, args.verbose)
        print(Fore.CYAN + Style.BRIGHT + "\n========== Test Summary ==========")
        total_vulns = len(ssrf_test.vulnerabilities_found) + len(open_redirect_test.vulnerabilities_found)
        print(Fore.CYAN + f"Total vulnerabilities found: {total_vulns}")
        if ssrf_test.vulnerabilities_found:
            print(Fore.MAGENTA + Style.BRIGHT + "\n--- SSRF Vulnerabilities ---")
            for vuln in ssrf_test.vulnerabilities_found:
                print(Fore.RED + f"- {vuln['method']} {vuln['url']}")
                print(f"  Headers: {vuln['headers']}")
                print(Fore.YELLOW + f"  Analysis: {vuln['analysis']}")
                print(Fore.RED + "-" * 80)
        if open_redirect_test.vulnerabilities_found:
            print(Fore.MAGENTA + Style.BRIGHT + "\n--- Open Redirect Vulnerabilities ---")
            for vuln in open_redirect_test.vulnerabilities_found:
                print(Fore.RED + f"- {vuln['method']} {vuln['url']}")
                print(f"  Headers: {vuln['headers']}")
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
