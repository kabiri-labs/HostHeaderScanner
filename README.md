# HostHeaderScanner

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**HostHeaderScanner** is a powerful tool designed to detect Host Header Injection vulnerabilities, including SSRF (Server-Side Request Forgery) and Open Redirects. It automates the testing process by sending crafted HTTP requests with manipulated `Host` headers to the target URL and analyzes the responses to identify potential vulnerabilities.

## Features

- **SSRF Detection**: Identifies potential SSRF vulnerabilities by analyzing response times and response contents.
- **Open Redirect Detection**: Detects open redirect vulnerabilities caused by manipulated `Host` headers.
- **Multi-threading Support**: Speeds up testing using concurrent threads.
- **Customizable Verbosity**: Offers different levels of verbosity to control the amount of output.
- **Output Saving**: Saves results to a file in JSON or Markdown format.

## Installation

### Prerequisites

- Python 3.6 or higher

### Clone the Repository

```bash
git clone https://github.com/inpentest/HostHeaderScanner.git
cd HostHeaderScanner
