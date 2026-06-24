# HostHeaderScanner v1.5.0

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![GitHub Stars](https://img.shields.io/github/stars/kabiri-labs/HostHeaderScanner.svg?style=social&label=Star)](https://github.com/kabiri-labs/HostHeaderScanner)

**HostHeaderScanner** is an advanced tool designed to detect Host Header Injection vulnerabilities, including Server-Side Request Forgery (SSRF), Open Redirects, and other anomalies. It uses sophisticated techniques, including crafted HTTP requests and comprehensive analysis, to help secure web applications effectively.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Options](#options)
  - [Examples](#examples)
- [Output](#output)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Contact](#contact)

---

## Features

- **Reflection-based Host Header Injection**: Injects a unique random marker host across `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `Forwarded` and 15+ other routing headers, then detects reflection in the response body, the `Location` header and other response headers. Because the marker is unique, findings are high-confidence (cache poisoning / password-reset poisoning / link poisoning).
- **Raw HTTP Validation Bypasses**: Uses a built-in raw HTTP/1.1 client (not `requests`) to send malformed requests that bypass Host validation: **duplicate `Host` headers**, **absolute-URI request lines**, **indented (line-folded) headers** and host overrides.
- **Confirmed Web Cache Poisoning**: Adds a unique cache-buster, sends a poisoning request via unkeyed headers, then re-requests the same URL *without* the header. A surviving marker confirms the response is cached and served to other users, and `X-Cache`/`Age`/`CF-Cache-Status` are reported.
- **Host-based Access Control Bypass**: Detects 401/403 endpoints that become reachable when presenting an internal host or client IP (`Host: localhost`, `X-Forwarded-For: 127.0.0.1`, ...), plus front-end path-override headers (`X-Original-URL`, `X-Rewrite-URL`).
- **SSRF Detection**: Combines response-time deviation, internal-target indicators and header anomalies behind a weighted scoring model to reduce false positives.
- **Open Redirect Detection**: Flags redirects whose `Location` host matches an injected Host value.
- **URL Parameter SSRF**: Probes common parameters (`url`, `next`, `redirect`, ...) against internal targets with baseline differencing.
- **OOB Correlation**: Accepts an `--oob` domain that is embedded into payloads as a unique subdomain so interactions can be correlated on your own collaborator/listener.
- **Multi-threaded Scanning**: Uses a bounded `ThreadPoolExecutor` with connection pooling and automatic retries.
- **Flexible Requests**: Configurable HTTP methods, per-request timeout, custom headers, upstream proxy and optional TLS verification bypass.
- **Customizable Verbosity**: Offers different levels of verbosity to control the amount of output.
- **Exportable Reports**: Saves results in JSON or Markdown format for easy documentation.
- **Graceful Interruption Handling**: Allows interruption with `Ctrl+C` and exits gracefully without data loss.

---

## Installation

### Prerequisites

- **Python 3.6** or higher.

### Clone the Repository

```bash
git clone https://github.com/kabiri-labs/HostHeaderScanner.git
cd HostHeaderScanner
```

### Install Dependencies

Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

Alternatively, install them individually:

```bash
pip install requests tqdm colorama
```

---

## Usage

```bash
python host_header_scanner.py [options] <target_url>
```

### Basic Usage

```bash
python host_header_scanner.py http://example.com
```

### Options

- `<target_url>`: **(Required)** The target URL to scan.
- `--oob <domain>`: Specify an Out-of-Band (OOB) domain for advanced SSRF correlation.
- `--threads <number>`: Number of concurrent threads (default is 5). Must be between 1 and 20.
- `--timeout <seconds>`: Per-request timeout in seconds (default is 10).
- `--methods <list>`: Comma-separated HTTP methods to test (default `GET`, e.g. `GET,POST`).
- `--header <"Name: Value">` or `-H`: Add a custom request header. Repeatable.
- `--proxy <url>`: Route traffic through an upstream proxy (e.g. `http://127.0.0.1:8080`).
- `--insecure` or `-k`: Disable TLS certificate verification.
- `--verbose <level>`: Verbosity level (1 or 2). Level 2 provides more detailed output.
- `--output <file>` or `-o <file>`: Output file to save the test results (supports `.json` and `.md` extensions).

### Examples

#### Specify Number of Threads

```bash
python host_header_scanner.py http://example.com --threads 10
```

#### Verbosity Level 2

```bash
python host_header_scanner.py http://example.com --verbose 2
```

#### Save Results to a File

```bash
python host_header_scanner.py http://example.com -o results.json
```

#### Use an OOB Domain

```bash
python host_header_scanner.py http://example.com --oob oob.example.com
```

#### Test Additional Methods and Route Through a Proxy

```bash
python host_header_scanner.py http://example.com --methods GET,POST --proxy http://127.0.0.1:8080
```

#### Send Custom Headers (e.g. Authentication)

```bash
python host_header_scanner.py http://example.com -H "Authorization: Bearer <token>" -H "Cookie: session=abc"
```

#### Full Command

```bash
python host_header_scanner.py http://example.com --threads 10 --timeout 8 --verbose 2 --output results.md --oob oob.example.com
```

### Interrupting the Program

- Press `Ctrl+C` at any time to stop the execution gracefully.

---

## Output

The tool provides a detailed summary of the findings, highlighting any vulnerabilities detected. The output includes:

- **Test Type**: SSRF, Open Redirect, or Host Header Injection.
- **URL Tested**: The target URL that was tested.
- **HTTP Method Used**: GET, POST, PUT, DELETE.
- **Manipulated Headers**: The HTTP headers used in the request.
- **Status Code Received**: HTTP response status code.
- **Response Time**: Time taken to receive a response.
- **Header Anomalies**: Details of any discrepancies in HTTP headers between baseline and test responses (e.g., changes to `Content-Type` or `Vary` headers).
- **Analysis**: Interpretation of the results, including response time anomalies, header anomalies, and potential OOB interactions.

### Sample Output

```
HostHeaderScanner 1.4.0
GitHub: https://github.com/kabiri-labs/HostHeaderScanner

Target URL: http://example.com
Original Host: example.com
Methods: GET
Using 5 threads (timeout 10.0s).
Verbosity level set to 1.

Starting Host Header Injection Testing...
Host Header Injection Testing: 100%|████████████████████████| 27/27 [00:06<00:00, 4.34test/s]

[!] Host Header Injection Finding!
URL: http://example.com/
Method: GET
Header: X-Forwarded-Host
Payload: 834503a3f66d.example-collab.com
Status Code: 302
Response Time: 0.01s
Analysis: Injected host reflected in 'Location' header: https://834503a3f66d.example-collab.com/login Injected host reflected in response body (cache/link poisoning).
--------------------------------------------------------------------------------

========== Test Summary ==========
Total findings: 1

--- Host Header Injection ---
- GET http://example.com/
  Header/Parameter: X-Forwarded-Host
  Payload: 834503a3f66d.example-collab.com
  Analysis: Injected host reflected in 'Location' header: https://834503a3f66d.example-collab.com/login Injected host reflected in response body (cache/link poisoning).
--------------------------------------------------------------------------------
===================================
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository**: Click the "Fork" button at the top-right corner of this page.
2. **Clone Your Fork**: Clone your forked repository to your local machine.

   ```bash
   git clone https://github.com/your-username/HostHeaderScanner.git
   ```

3. **Create a Branch**: Create a new branch for your feature or bug fix.

   ```bash
   git checkout -b feature/YourFeature
   ```

4. **Make Changes**: Add your improvements or fixes.

5. **Commit Changes**: Commit your changes with a descriptive message.

   ```bash
   git commit -m "Add new feature to improve scanning speed"
   ```

6. **Push to GitHub**: Push your changes to your forked repository.

   ```bash
   git push origin feature/YourFeature
   ```

7. **Open a Pull Request**: Navigate to the original repository and click on "New Pull Request".

Please ensure your code adheres to the existing style and includes appropriate error handling.

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

**HostHeaderScanner** is intended for educational and authorized testing purposes only. Unauthorized use of this tool against systems without explicit permission is illegal and unethical. The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

---

## Contact

For support or inquiries:

- **Email**: [certification.kabiri@gmail.com](mailto:certification.kabiri@gmail.com)
- **GitHub Issues**: [Create an Issue](https://github.com/kabiri-labs/HostHeaderScanner/issues)

Feel free to open an issue or pull request for any bugs, feature requests, or questions.

---

**Star this project** ⭐ if you find it useful!



