# ssl_test.py
import ssl
import socket
from urllib.parse import urlparse

def check_ssl_cert(domain):
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"Connected to {domain}. Cert issued by: {cert['issuer']}")
                return cert
    except Exception as e:
        print(f"SSL check failed for {domain}: {e}")
        return None

if __name__ == "__main__":
    domain = input("Enter domain to check SSL certificate: ").strip()
    cert_info = check_ssl_cert(domain)
    if cert_info:
        print("SSL Certificate looks legitimate.")
    else:
        print("Possible SSL interception or redirect!")
