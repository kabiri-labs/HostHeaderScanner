# HostHeaderScanner v1.2

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![GitHub Stars](https://img.shields.io/github/stars/inpentest/HostHeaderScanner.svg?style=social&label=Star)](https://github.com/inpentest/HostHeaderScanner)

**HostHeaderScanner** is a powerful and efficient tool designed to detect Host Header Injection vulnerabilities, including Server-Side Request Forgery (SSRF) and Open Redirects. By automating the testing process with crafted HTTP requests and analyzing responses, it helps you secure your web applications effectively.

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

- **Comprehensive Vulnerability Detection**: Identifies Host Header Injection vulnerabilities, including SSRF and Open Redirects.
- **Multi-threaded Scanning**: Accelerates the testing process using concurrent threads.
- **Detailed Analysis**: Provides in-depth analysis of responses to highlight potential vulnerabilities.
- **Customizable Verbosity**: Offers different levels of verbosity to control the amount of output.
- **Exportable Reports**: Saves results in JSON or Markdown format for easy documentation.
- **Graceful Interruption Handling**: Allows interruption with `Ctrl+C` and exits gracefully without data loss.

---

## Installation

### Prerequisites

- **Python 3.6** or higher.

### Clone the Repository

```bash
git clone https://github.com/inpentest/HostHeaderScanner.git
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
- `--oob <domain>`: Specify an out-of-band (OOB) domain for advanced testing.
- `--threads <number>`: Number of concurrent threads (default is 5). Must be between 1 and 20.
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

#### Full Command

```bash
python host_header_scanner.py http://example.com --threads 10 --verbose 2 --output results.md --oob oob.example.com
```

### Interrupting the Program

- Press `Ctrl+C` at any time to stop the execution gracefully.

---

## Output

The tool provides a detailed summary of the findings, highlighting any vulnerabilities detected. The output includes:

- **Test Type**: SSRF or Open Redirect.
- **URL Tested**: The target URL that was tested.
- **HTTP Method Used**: GET, POST, PUT, DELETE.
- **Manipulated Headers**: The HTTP headers used in the request.
- **Status Code Received**: HTTP response status code.
- **Response Time**: Time taken to receive a response.
- **Analysis**: Interpretation of the results.

### Sample Output

```
HostHeaderScanner 1.2
GitHub: https://github.com/inpentest/HostHeaderScanner

Target URL: http://example.com
Original Host: example.com
Using 5 threads.
Verbosity level set to 1.

Starting SSRF Tests...
SSRF Testing: 100%|█████████████████████████████████████████| 780/780 [00:30<00:00, 25.50test/s]

[!] SSRF Potential Vulnerability Detected!
URL: http://example.com/
Method: PUT
Headers: {'Host': '127.0.0.1:3306'}
Status Code: 404
Response Time: 1.25s
Analysis: Response time (1.25s) is 5.00 standard deviations slower than the mean (0.20s).
--------------------------------------------------------------------------------

========== Test Summary ==========
Total vulnerabilities found: 1

--- SSRF Vulnerabilities ---
- PUT http://example.com/
  Headers: {'Host': '127.0.0.1:3306'}
  Analysis: Response time (1.25s) is 5.00 standard deviations slower than the mean (0.20s).
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
- **GitHub Issues**: [Create an Issue](https://github.com/inpentest/HostHeaderScanner/issues)

Feel free to open an issue or pull request for any bugs, feature requests, or questions.

---

**Star this project** ⭐ if you find it useful!
