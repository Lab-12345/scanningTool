from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import json
import http.client
import ssl
import urllib.parse
import time

app = Flask(__name__)

def crawl_page(url):
    """Crawl a webpage to extract forms, input fields, links, headers, and scripts."""
    start_time = time.time()
    try:
        headers = {'User-Agent': 'VulnScanner/1.0'}
        response = requests.get(url, headers=headers, timeout=3, verify=False)
        print(f"Response status for {url}: {response.status_code} (Time: {time.time() - start_time:.2f}s)")
        if response.status_code != 200:
            print(f"Failed to access {url}: Status {response.status_code}")
            return [], [], [], {}, []
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = [
            {
                'action': urljoin(url, form.get('action', url)),
                'method': form.get('method', 'GET').upper(),
                'inputs': [inp.get('name') for inp in form.find_all(['input', 'select']) if inp.get('name')]
            } for form in soup.find_all('form')
        ]
        
        inputs = [inp.get('name') for inp in soup.find_all(['input', 'select']) if inp.get('name')]
        links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)][:5]
        headers = dict(response.headers)
        scripts = [script.get_text() for script in soup.find_all('script') if script.get_text()]
        
        print(f"Crawled {url}: {len(forms)} forms, {len(inputs)} inputs, {len(links)} links, {len(scripts)} scripts")
        print(f"Form details: {forms}")
        print(f"Input fields: {inputs}")
        print(f"Scripts: {[s[:50] + '...' for s in scripts]}")
        print(f"Crawl time: {time.time() - start_time:.2f}s")
        return forms, inputs, links, headers, scripts
    except Exception as e:
        print(f"Error crawling {url}: {e}")
        return [], [], [], {}, []
    finally:
        print(f"Total crawl time: {time.time() - start_time:.2f}s")

def test_vulnerability(url, payload=None, param_name="q", method="GET", headers=None, scripts=None):
    """Test a URL for OWASP Top 10 vulnerabilities with accurate reporting."""
    start_time = time.time()
    try:
        if headers is None:
            headers = {'User-Agent': 'VulnScanner/1.0'}
        vulnerabilities = []
        
        # A03: Injection (XSS, SQLi, etc.)
        if payload:
            print(f"Testing {url} with payload '{payload}' on param '{param_name}' ({method})")
            try:
                if method == "GET":
                    response = requests.get(url, params={param_name: payload}, headers=headers, timeout=3, verify=False)
                else:
                    response = requests.post(url, data={param_name: payload}, headers=headers, timeout=3, verify=False)
                
                print(f"Response status: {response.status_code}, Text: {response.text[:200]}...")
                
                # Reflected XSS
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "High",
                        "evidence": f"Payload '{payload}' reflected in response",
                        "url": url
                    })
                
                # DOM-based XSS
                if scripts:
                    for script in scripts:
                        if re.search(r'eval\(|innerHTML|document\.write\(|document\.location', script, re.IGNORECASE):
                            vulnerabilities.append({
                                "type": "DOM-based XSS",
                                "severity": "High",
                                "evidence": f"Vulnerable JavaScript pattern in script: {script[:50]}...",
                                "url": url
                            })
                
                # SQL Injection
                sqli_pattern = re.compile(r"sql|mysql|sqlite|postgresql|syntax error|unclosed quotation|incorrect syntax|you have an error in your sql syntax", re.IGNORECASE)
                if sqli_pattern.search(response.text):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "evidence": f"SQL error detected with payload '{payload}'",
                        "url": url
                    })
                
                # Command Injection
                cmdi_pattern = re.compile(r"dir|ls|cat|whoami|ping|exec|system|shell", re.IGNORECASE)
                if cmdi_pattern.search(response.text):
                    vulnerabilities.append({
                        "type": "Command Injection",
                        "severity": "Critical",
                        "evidence": f"Command output detected with payload '{payload}'",
                        "url": url
                    })
                
                # File Inclusion
                if re.search(r"root:.*:0:0:|/etc/passwd", response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "File Inclusion",
                        "severity": "Critical",
                        "evidence": f"Sensitive file content detected with payload '{payload}'",
                        "url": url
                    })
            except Exception as e:
                print(f"Error injecting payload '{payload}' on {url}: {e}")
        
        # A01: Broken Access Control
        if not payload:
            admin_urls = [urljoin(url, path) for path in ['/admin', '/dashboard']][:2]
            for admin_url in admin_urls:
                try:
                    response = requests.get(admin_url, headers=headers, timeout=3, verify=False)
                    print(f"Testing Broken Access Control on {admin_url}: Status {response.status_code}")
                    if response.status_code == 200 and 'login' not in response.text.lower():
                        vulnerabilities.append({
                            "type": "Broken Access Control",
                            "severity": "High",
                            "evidence": f"Accessible unprotected endpoint: {admin_url}",
                            "url": admin_url
                        })
                except Exception as e:
                    print(f"Error testing {admin_url}: {e}")
        
        # A02: Cryptographic Failures (HSTS check)
        parsed_url = urllib.parse.urlparse(url)
        try:
            conn = http.client.HTTPSConnection(parsed_url.netloc, timeout=3, context=ssl._create_unverified_context())
            conn.request("GET", parsed_url.path or '/')
            response = conn.getresponse()
            response_headers = dict(response.getheaders())
            print(f"HSTS check on {url}: Headers {response_headers}")
            if 'Strict-Transport-Security' not in response_headers:
                vulnerabilities.append({
                    "type": "Cryptographic Failures",
                    "severity": "Medium",
                    "evidence": "Missing HSTS header",
                    "url": url
                })
            conn.close()
        except Exception as e:
            print(f"Error checking HTTPS for {url}: {e}")
        
        # A05: Security Misconfiguration
        if headers.get('Server', '').lower().startswith(('apache', 'nginx', 'iis')):
            vulnerabilities.append({
                "type": "Security Misconfiguration",
                "severity": "Medium",
                "evidence": f"Server header exposes software: {headers['Server']}",
                "url": url
            })
        if headers.get('X-Powered-By'):
            vulnerabilities.append({
                "type": "Security Misconfiguration",
                "severity": "Low",
                "evidence": f"X-Powered-By header exposes tech: {headers['X-Powered-By']}",
                "url": url
            })
        
        # A06: Vulnerable and Outdated Components
        if 'Server' in headers and re.search(r'apache/2\.[0-2]|nginx/1\.[0-9]', headers['Server'], re.IGNORECASE):
            vulnerabilities.append({
                "type": "Vulnerable and Outdated Components",
                "severity": "High",
                "evidence": f"Outdated server version: {headers['Server']}",
                "url": url
            })
        
        # A07: Identification and Authentication Failures
        try:
            login_url = urljoin(url, '/login.php')
            response = requests.get(login_url, headers=headers, timeout=3, verify=False)
            print(f"Testing login page {login_url}: Status {response.status_code}")
            if response.status_code == 200 and 'password' in response.text.lower() and not re.search(r'csrf|token', response.text, re.IGNORECASE):
                vulnerabilities.append({
                    "type": "Identification and Authentication Failures",
                    "severity": "Medium",
                    "evidence": "Login form lacks CSRF protection",
                    "url": login_url
                })
        except Exception as e:
            print(f"Error checking login page {login_url}: {e}")
        
        # A08: Software and Data Integrity Failures
        if 'Content-Security-Policy' not in response_headers:
            vulnerabilities.append({
                "type": "Software and Data Integrity Failures",
                "severity": "Medium",
                "evidence": "Missing Content-Security-Policy header",
                "url": url
            })
        
        # A09: Security Logging and Monitoring Failures
        try:
            response = requests.get(url, params={'test': '1; DROP TABLE users; --'}, headers=headers, timeout=3, verify=False)
            print(f"Testing logging on {url}: Status {response.status_code}")
            if response.status_code == 200 and not re.search(r'error|blocked|forbidden', response.text, re.IGNORECASE):
                vulnerabilities.append({
                    "type": "Security Logging and Monitoring Failures",
                    "severity": "Low",
                    "evidence": "Suspicious request not blocked or logged",
                    "url": url
                })
        except Exception as e:
            print(f"Error testing logging for {url}: {e}")
        
        # A10: Server-Side Request Forgery (SSRF)
        ssrf_payload = 'http://169.254.169.254/latest/meta-data/'
        try:
            response = requests.get(url, params={param_name: ssrf_payload}, headers=headers, timeout=3, verify=False)
            print(f"Testing SSRF on {url}: Status {response.status_code}")
            if 'instance-id' in response.text or 'iam' in response.text:
                vulnerabilities.append({
                    "type": "Server-Side Request Forgery (SSRF)",
                    "severity": "Critical",
                    "evidence": f"SSRF payload '{ssrf_payload}' returned sensitive data",
                    "url": url
                })
        except Exception as e:
            print(f"Error testing SSRF for {url}: {e}")
        
        print(f"Found vulnerabilities: {vulnerabilities} (Time: {time.time() - start_time:.2f}s)")
        return vulnerabilities
    except Exception as e:
        print(f"Error testing {url}: {e}")
        return []
    finally:
        print(f"Total test time: {time.time() - start_time:.2f}s")

def scan_site(base_url):
    """Scan a website for OWASP Top 10 vulnerabilities."""
    start_time = time.time()
    vulnerabilities = []
    try:
        forms, inputs, links, headers, scripts = crawl_page(base_url)
        print(f"Forms: {forms}, Inputs: {inputs}, Links: {links}, Headers: {headers}")
        
        # Load payloads
        try:
            with open("payloads.txt", "r") as f:
                payloads = f.read().splitlines()
            print(f"Loaded payloads: {payloads}")
            if not payloads:
                print("Error: payloads.txt is empty")
                payloads = [
                    "<script>alert('XSS')</script>",
                    "\"><img src=x onerror=alert('XSS')>",
                    "<img src='javascript:alert(1)'>",
                    "' OR '1'='1",
                    "1; DROP TABLE users; --"
                ]
        except FileNotFoundError:
            print("Error: payloads.txt not found")
            payloads = [
                "<script>alert('XSS')</script>",
                "\"><img src=x onerror=alert('XSS')>",
                "<img src='javascript:alert(1)'>",
                "' OR '1'='1",
                "1; DROP TABLE users; --"
            ]
        
        # Limit payloads for performance
        payloads = payloads[:3]
        
        # Test forms (POST)
        for form in forms[:1]:
            action = form['action']
            print(f"Testing form action: {action}")
            for input_name in form['inputs'][:1]:
                print(f"Testing input: {input_name}")
                for payload in payloads:
                    results = test_vulnerability(action, payload, input_name, method="POST", headers=headers, scripts=scripts)
                    for result in results:
                        vulnerabilities.append({"form_action": action, "input": input_name, **result})
        
        # Test inputs (GET)
        for input_name in inputs[:1]:
            print(f"Testing input (GET): {input_name}")
            for payload in payloads:
                results = test_vulnerability(base_url, payload, input_name, method="GET", headers=headers, scripts=scripts)
                for result in results:
                    vulnerabilities.append({"input": input_name, **result})
        
        # Test non-payload-based vulnerabilities
        results = test_vulnerability(base_url, headers=headers, scripts=scripts)
        vulnerabilities.extend(results)
        
        if vulnerabilities:
            with open('results.json', 'w') as f:
                json.dump(vulnerabilities, f, indent=4)
            print(f"Logged {len(vulnerabilities)} vulnerabilities to results.json")
        else:
            print("No vulnerabilities found.")
        
        return vulnerabilities
    except Exception as e:
        print(f"Error in scan_site: {e}")
        return []
    finally:
        print(f"Total scan time: {time.time() - start_time:.2f}s")

@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle scan requests and display results."""
    start_time = time.time()
    url = request.form.get('url')
    error = None
    vulnerabilities = []
    
    if not url:
        error = "No URL provided."
    else:
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            vulnerabilities = scan_site(url)
        except Exception as e:
            error = f"Error scanning site: {str(e)}"
    
    print(f"Rendering results: {vulnerabilities}, Error: {error} (Total time: {time.time() - start_time:.2f}s)")
    return render_template('results.html', vulnerabilities=vulnerabilities, error=error, scanned_url=url)

if __name__ == '__main__':
    app.run(debug=True)