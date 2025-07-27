Web Vulnerability Scanner

Overview

This project is a web vulnerability scanner developed to identify vulnerabilities listed in the OWASP Top 10, with a focus on Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF). The scanner was tested on the Damn Vulnerable Web Application (DVWA) hosted locally via XAMPP at http://localhost/DVWA-master/DVWA-master/. It aims to provide a user-friendly tool with optimized performance and downloadable reports.

Features





Vulnerability Detection: Identifies reflected payloads and DOM-based XSS (e.g., patterns like eval and innerHTML in scripts).



Optimized Performance: Reduces scan time to under 3 seconds by limiting payloads and form submissions.



User Interface: Includes a centered index.html and a downloadable report feature in results.html.



Error Fixes:





Resolved strftime errors by using JavaScript Date.toISOString().



Fixed incorrect HSTS reporting linked to login.php by adding a URL field.

Installation





Clone the repository:

git clone <repository-url>



Set up a local web server (e.g., XAMPP) and host the DVWA application at http://localhost/DVWA-master/DVWA-master/.



Place the scanner files in the appropriate directory within your web server.



Access the scanner through your browser at the configured URL.

Usage





Navigate to the scanner's index.html in your browser.



Enter the target URL (e.g., http://localhost/DVWA-master/DVWA-master/vulnerabilities/).



Run the scan and view results in the browser or download the report from results.html.

Challenges and Solutions





Slow Scans: Optimized by limiting payloads and form submissions to achieve scan times under 3 seconds.



DOM-based XSS Detection: Implemented script pattern analysis to detect vulnerabilities like eval and innerHTML.



Incorrect URL Reporting: Fixed HSTS misreporting by adding a dedicated URL field.



Template Errors: Replaced strftime with Date.toISOString() for consistent timestamp handling.

Future Enhancements





Add advanced CSRF detection mechanisms.



Expand support for additional OWASP Top 10 vulnerabilities.



Improve UI for better user interaction and accessibility.

Testing

The scanner was tested on:





Environment: Local XAMPP server



Target: DVWA at http://localhost/DVWA-master/DVWA-master/vulnerabilities/



Date: July 8, 2025

Author





Submitted by: Laba Kumar Kalita

License

This project is licensed under the MIT License.
