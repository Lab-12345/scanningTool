# Web Vulnerability Scanner

## Overview

A Python-based web vulnerability scanner designed to detect OWASP Top 10 vulnerabilities, focusing on XSS and CSRF. Tested on Damn Vulnerable Web Application (DVWA) hosted via XAMPP at `http://localhost/DVWA-master/DVWA-master/`.

## Features

- Detects reflected/DOM-based XSS, CSRF, SQL Injection, and Cryptographic Failures.
- Optimized with limited payloads (3), forms (1), inputs (1), and 3-second timeout.
- User-friendly Flask-based UI (`index.html`) with downloadable reports (`results.html`).
- Fixes for `strftime` errors and incorrect `form_action` reporting.

## Tools

- **Python**: Core logic.
- **Flask**: Web interface.
- **Requests**: HTTP crawling.
- **BeautifulSoup**: HTML parsing.
- **HTML/JavaScript**: UI and report download.
- **XAMPP**: Local DVWA hosting.

## Installation

1. Install Python 3.x and XAMPP.
2. Set up DVWA in XAMPP.
3. Install dependencies:

   ```bash
   pip install flask requests beautifulsoup4
   ```
4. Clone and run:

   ```bash
   git clone <repository-url>
   cd vuln-scan
   python app.py
   ```

## Usage

- Access `http://localhost:5000`.
- Input target URL (e.g., `http://localhost/DVWA-master/DVWA-master/`).
- Run scan and download report from `results.html`.

## Implementation

- **Crawling**: Extracts forms, inputs, links, headers, scripts.
- **Payload Injection**: Tests payloads like `<script>alert("XSS")</script>`.
- **Detection**: Analyzes responses for reflected payloads and scripts for DOM-based XSS.
- **Optimizations**: Limits requests for faster scans.
- **Fixes**: Corrects HSTS and `strftime` issues.

## Testing

- Tested on DVWA endpoints: `/vulnerabilities/csrf/`, `/xss_d/`.
- Detected issues: Missing HSTS, DOM-based XSS, CSRF.

## Author

Laba Kumar Kalita

## License

MIT License
