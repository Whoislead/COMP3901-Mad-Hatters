import requests
import socket 
import shodan
from shodan import Shodan
from collections import Counter
from urllib.parse import urlparse

# === CONFIG ===
SHODAN_API_KEY = "Ims2KdUauqQBpLcooMwzVvguk7IxneJD"

# === Validate Domain ===
def validate_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# === Query crt.sh ===
def fetch_certificates(domain):
    url = f"https://crt.sh/?q=%25{domain}&output=json"

    try:
        response = requests.get(url, timeout=30)
        return response.json() if response.status_code == 200 else []
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return []

# === Analyze Certificates ===
def analyze_certs(certs, domain):
    if not certs:
        print("[*] No certs found.")
        return

    print(f"\n[*] Found {len(certs)} certs for {domain}")
    issuers = Counter()
    wildcards = 0

    for cert in certs:
        name = cert.get('common_name') or cert.get('name_value', '')
        issuer = cert.get('issuer_name', 'Unknown')
        issuers[issuer] += 1
        if "*." in name:
            wildcards += 1

    print("\n[*] Issuers detected:")
    for i, count in issuers.items():
        print(f"  - {i}: {count} certs")

    if len(issuers) > 3:
        print("[!] Multiple distinct issuers — may indicate cloned domain behavior.")
    if wildcards > 2:
        print("[!] Excessive wildcard certs — check for generic phishing attempts.")

# === Shodan Lookup ===
def shodan_lookup(domain):
    try:
        print(f"\n[*] Shodan Search for: {domain}")
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(f'hostname:{domain}')
        
        if results['total'] == 0:
            print("[*] No Shodan results.")
            return

        for match in results['matches']:
            ip = match.get('ip_str', 'N/A')
            port = match.get('port', 'N/A')
            org = match.get('org', 'N/A')
            data = match.get('data', '')

            print(f"\n[+] IP: {ip}  Port: {port}  Org: {org}")
            if "captive" in data.lower() or "login" in data.lower():
                print("[!] Possible captive portal or phishing signature detected.")

    except shodan.exception.APIError as e:
        print(f"[!] Shodan API error: {e}")

# === Main Logic ===
def check_domain(domain):
    print(f"\n=== Checking {domain} ===")

    if not validate_domain(domain):
        print("[X] Invalid domain or could not resolve DNS.")
        return

    certs = fetch_certificates(domain)
    analyze_certs(certs, domain)
    shodan_lookup(domain)

# === Example Usage ===
if __name__ == "__main__":
    domain = input("Enter domain (e.g. accounts.google.com): ").strip().lower()
    check_domain(domain)
