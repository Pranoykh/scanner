# Web Application Vulnerability Scanner

A Python-based CLI tool to scan web applications for common vulnerabilities such as SQL Injection, XSS, and open redirects.

## Features
- Scan a target URL for common web vulnerabilities
- Detect SQL Injection, XSS, and open redirect issues
- Simple command-line interface

## Usage
```sh
python scanner.py --url https://example.com
```

## Requirements
- Python 3.8+
- `requests` library

## Setup
1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
2. Run the scanner:
   ```sh
   python scanner.py --url <target_url>
   ```

## Disclaimer
This tool is for educational and authorized testing purposes only. Do not use it on systems you do not own or have explicit permission to test.
