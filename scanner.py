import argparse
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re

# Simple payloads for demonstration
SQLI_PAYLOADS = ["' OR '1'='1' --","admin'--","' UNION SELECT 1,2,3 --","' or 1=1 #","\" OR \"\"=\"","1' ORDER BY 1--",]
XSS_PAYLOADS = [ "<script>alert('XSS');</script>","<img src=x onerror=alert('XSS')>","<svg/onload=alert('XSS')>","'';!--\"<XSS>=&{()}",]
REDIRECT_PAYLOADS = ['//evil.com', 'http://evil.com']


def scan_sql_injection(url, log_list=None):
    print("[+] Scanning for SQL Injection...")
    vulnerable = False
    error_patterns = [
        re.compile(r"sql syntax", re.I),
        re.compile(r"mysql", re.I),
        re.compile(r"syntax error", re.I),
        re.compile(r"unclosed quotation", re.I),
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning:.*\Wmysql_", re.I),
    ]
    for payload in SQLI_PAYLOADS:
        test_url = f"{url}?id={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            for pattern in error_patterns:
                m = pattern.search(r.text)
                if m:
                    evidence = m.group(0)
                    msg = f"[!] Possible SQL Injection vulnerability at: {test_url}\n    Evidence: {evidence}\n    Severity: High"
                    print(msg)
                    if log_list is not None:
                        log_list.append({'type': 'SQL Injection', 'url': test_url, 'evidence': evidence, 'severity': 'High'})
                    vulnerable = True
                    break
        except Exception:
            pass
    if not vulnerable:
        print("[-] No SQL Injection vulnerabilities found.")

def scan_xss(url, log_list=None):
    print("[+] Scanning for XSS...")
    vulnerable = False
    xss_patterns = [
        re.compile(r'<script.*?>.*?</script>', re.I|re.S),
        re.compile(r'<.*?on\w+\s*=\s*"[^"]*".*?>', re.I),
        re.compile(r'<svg.*?onload=.*?>', re.I),
    ]
    for payload in XSS_PAYLOADS:
        test_url = f"{url}?q={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            for pattern in xss_patterns:
                m = pattern.search(r.text)
                if m:
                    evidence = m.group(0)
                    msg = f"[!] Possible XSS vulnerability at: {test_url}\n    Evidence: {evidence}\n    Severity: Medium"
                    print(msg)
                    if log_list is not None:
                        log_list.append({'type': 'XSS', 'url': test_url, 'evidence': evidence, 'severity': 'Medium'})
                    vulnerable = True
                    break
        except Exception:
            pass
    if not vulnerable:
        print("[-] No XSS vulnerabilities found.")

def scan_open_redirect(url, log_list=None):
    print("[+] Scanning for Open Redirect...")
    vulnerable = False
    redirect_pattern = re.compile(r'(https?:)?//[\w\.-]+', re.I)
    for payload in REDIRECT_PAYLOADS:
        test_url = f"{url}?next={payload}"
        try:
            r = requests.get(test_url, allow_redirects=False, timeout=5)
            location = r.headers.get('Location', '')
            if r.status_code in [301, 302] and redirect_pattern.match(location) and payload in location:
                evidence = location
                msg = f"[!] Possible Open Redirect vulnerability at: {test_url}\n    Evidence: {evidence}\n    Severity: Medium"
                print(msg)
                if log_list is not None:
                    log_list.append({'type': 'Open Redirect', 'url': test_url, 'evidence': evidence, 'severity': 'Medium'})
                vulnerable = True
        except Exception:
            pass
    if not vulnerable:
        print("[-] No Open Redirect vulnerabilities found.")

def main():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument('--url', required=True, help='Target URL to scan (e.g., https://example.com/page)')
    args = parser.parse_args()
    url = args.url.rstrip('/')
    # Fetch and parse the page with BeautifulSoup
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        title = soup.title.string if soup.title else 'No title found'
        print(f"[+] Page title: {title}")
    except Exception as e:
        print(f"[!] Error fetching/parsing page: {e}")
    logs = []
    scan_sql_injection(url, logs)
    scan_xss(url, logs)
    scan_open_redirect(url, logs)
    print("\n--- Vulnerability Log ---")
    for entry in logs:
        print(f"Type: {entry['type']}\nURL: {entry['url']}\nEvidence: {entry['evidence']}\nSeverity: {entry['severity']}\n")

if __name__ == "__main__":
    main()
