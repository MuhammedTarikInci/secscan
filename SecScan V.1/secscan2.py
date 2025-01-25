import requests
from bs4 import BeautifulSoup
import socket
from urllib.parse import urljoin

# Common paths and payloads
COMMON_PATHS = ["/admin", "/login", "/wp-admin", "/phpmyadmin", "/config", "/backup"]
SQL_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users;", "' OR 1=1--"]
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

# URL validation function
def validate_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

# Directory scanning
def directory_scan(url):
    print("\n[Directory Scanning Started]")
    for path in COMMON_PATHS:
        full_url = urljoin(url, path)
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                print(f"[+] Directory Found: {full_url} (Potential sensitive information)")
            elif response.status_code == 403:
                print(f"[!] Forbidden Directory: {full_url} (Access might be restricted)")
        except requests.exceptions.RequestException as e:
            print(f"[-] Access Error: {full_url} ({e})")

# SQL Injection testing
def test_sql_injection(url):
    print("\n[SQL Injection Testing Started]")
    for payload in SQL_PAYLOADS:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if "sql" in response.text.lower() or "error" in response.text.lower():
                print(f"[+] Potential SQL Injection Vulnerability: {test_url}")
                print("    This vulnerability allows attackers to execute malicious queries on the database.")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {test_url} ({e})")

# XSS testing
def test_xss(url):
    print("\n[XSS Testing Started]")
    for payload in XSS_PAYLOADS:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=5)
            if payload in response.text:
                print(f"[+] Potential XSS Vulnerability: {url}?q={payload}")
                print("    This vulnerability allows attackers to execute malicious scripts in the user's browser.")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {url}?q={payload} ({e})")

# Open port scanning
def port_scan(host):
    print("\n[Open Port Scanning Started]")
    common_ports = [21, 22, 23, 80, 443, 8080]
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                if result == 0:
                    print(f"[+] Open Port: {port} (Potential for unauthorized access or data leakage)")
        except Exception as e:
            print(f"[-] Error in Port Scanning: {port} ({e})")

# Detailed explanations of vulnerabilities
def explain_vulnerability(vuln_type):
    explanations = {
        "SQL Injection": "This vulnerability allows attackers to execute malicious database queries, potentially compromising data security.",
        "XSS": "Cross-Site Scripting enables malicious scripts to run in a user's browser, often used to steal sensitive information.",
        "Directory Exposure": "Exposed directories may reveal sensitive files or server configurations, leading to unauthorized access.",
        "Open Port": "Open ports can allow unauthorized access to the server or lead to data breaches if not properly secured."
    }
    return explanations.get(vuln_type, "Unknown vulnerability type")

# Main function
def main():
    url = input("Enter the target URL: ").strip()
    url = validate_url(url)
    print(f"Starting scan for: {url}")
    
    # Get target IP address
    try:
        host = socket.gethostbyname(url.split("//")[1].split("/")[0])
        print(f"[i] Target IP: {host}")
    except Exception as e:
        print(f"[!] Failed to retrieve IP address: {e}")
        return

    # Perform scanning tasks
    directory_scan(url)
    test_sql_injection(url)
    test_xss(url)
    port_scan(host)
    
    # Print vulnerability explanations
    print("\n[Explanations]")
    print("1. SQL Injection:", explain_vulnerability("SQL Injection"))
    print("2. XSS:", explain_vulnerability("XSS"))
    print("3. Directory Exposure:", explain_vulnerability("Directory Exposure"))
    print("4. Open Port:", explain_vulnerability("Open Port"))

if __name__ == "__main__":
    main()
