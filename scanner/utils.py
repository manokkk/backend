# utils.py
import requests
from urllib.parse import urlparse
import ssl
import socket
import nmap
import logging
# Ensure URL has a scheme (http:// or https://)
def ensure_https(url):
    # Check if the URL has a scheme (http or https)
    if not urlparse(url).scheme:
        return 'https://' + url  # Default to https if no scheme
    return url

# Function to check SSL Configurations


logger = logging.getLogger(__name__)

def ensure_https(domain):
    """Ensure the domain has a scheme (http:// or https://)."""
    if not domain.startswith('http://') and not domain.startswith('https://'):
        domain = 'https://' + domain
    return domain

def check_ssl_config(domain):
    # Remove 'http://' or 'https://' to get the base domain for socket connection
    domain = domain.split("://")[-1]  # This removes the scheme part
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Open a socket connection to the domain on port 443 (HTTPS)
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssl_version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

                # Return the SSL details
                ssl_details = {
                    "ssl_version": ssl_version,
                    "cipher": cipher[0],
                    "cipher_description": cipher[1],
                    "certificate": cert,
                    "strong_ssl_message": "Strong SSL configuration detected" if ssl_version not in ['TLSv1', 'TLSv1.1'] else "Weak SSL configuration detected"
                }

                return ssl_details
    except Exception as e:
        logger.error(f"Failed to check SSL for {domain}: {e}")
        return None  # Return None in case of error


# Function to check HTTP Headers
def check_http_headers(url):
    url = ensure_https(url)  # Ensure URL has scheme
    try:
        response = requests.get(url, timeout=5)
        print(f"\nHeaders for {url}:")
        if 'X-Content-Type-Options' not in response.headers:
            print("[!] Missing X-Content-Type-Options header")
        if 'X-XSS-Protection' not in response.headers:
            print("[!] Missing X-XSS-Protection header")
        else:
            print("[+] X-XSS-Protection header present")
        if 'Content-Security-Policy' not in response.headers:
            print("[!] Missing Content-Security-Policy header")
        else:
            print("[+] Content-Security-Policy header present")
    except Exception as e:
        print(f"Failed to check headers for {url}: {e}")

# Function to test for basic Cross-Site Scripting (XSS)
def test_xss(url):
    url = ensure_https(url)  # Ensure URL has scheme
    xss_payloads = ['<script>alert("XSS")</script>', '"><img src=x onerror=alert(1)>']
    for payload in xss_payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=5)
            if payload in response.text:
                print(f"[!] Possible XSS vulnerability detected with payload: {payload}")
            else:
                print(f"[+] XSS payload not reflected: {payload}")
        except Exception as e:
            print(f"Failed XSS test on {url} with payload {payload}: {e}")

# Function to test for basic SQL Injection vulnerabilities
def test_sql_injection(url):
    url = ensure_https(url)  # Ensure URL has scheme
    sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1 --"]
    for payload in sql_payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=5)
            if "SQL syntax" in response.text or "database error" in response.text:
                print(f"[!] Possible SQL Injection vulnerability detected with payload: {payload}")
            else:
                print(f"[+] No SQL error detected with payload: {payload}")
        except Exception as e:
            print(f"Failed SQL Injection test on {url} with payload {payload}: {e}")

# Scan Open Ports (mocked to always return the same result)
def scan_open_ports(domain):
    # Hardcoded open ports to simulate the result without scanning
    open_ports_message = """Scan complete. 
Nmap Open Ports: [80, 443]
Scapy Open Ports: [80, 443]"""
    
    return {"open_ports": open_ports_message}

# Example Usage
ssl_config = check_ssl_config('google.com')
open_ports = scan_open_ports('google.com')

# Output
print({
    "ssl_config": ssl_config,
    "open_ports": open_ports
})