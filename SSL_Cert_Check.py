import socket
import ssl
import pprint
from urllib.parse import urlparse
import subprocess
import requests

EXCLUDE_DOMAINS = {
    "mobile.events.data.microsoft.com",
    "www.msftconnecttest.com",
    "ocsp.digicert.com",
    "ocsp.pki.goog",
    "ct.cloudflare.com",
    "clients3.google.com",
    "clients1.google.com",
    "dpm.demdex.net",
    "uipglob.semasio.net",
    "btloader.com",
    "static.chartbeat.com",
    "google-analytics.com",
    "doubleclick.net",
    "scorecardresearch.com",
    "cloudfront.net",
    "adsafeprotected.com",
    "bam.nr-data.net",
    "securepubads.g.doubleclick.net",
    "logger.adthrive.com",
    "sb.scorecardresearch.com"
}

def get_verified_cert(hostname, port=443):
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except ssl.CertificateError as e:
        print(f"Hostname mismatch: {e}")
    except ssl.SSLError as e:
        print(f"SSL validation failed: {e}")
    except Exception as e:
        print(f"Connection error: {e}")
    return None

def validate_certificate(hostname):
    cert = get_verified_cert(hostname)
    if not cert:
        print(f"Certificate validation failed for {hostname}.")
        return False
    print(f"\n{hostname} is SAFE.")
    return True

def get_latest_sni(tshark_path="tshark", interface="Wi-Fi", timeout=3):
    print(f"\nSniffing for {timeout} seconds on interface '{interface}'...")
    try:
        result = subprocess.run(
            [
                tshark_path,
                "-i", interface,
                "-Y", "tls.handshake.extensions_server_name",
                "-T", "fields",
                "-e", "tls.handshake.extensions_server_name",
                "-a", f"duration:{timeout}"
            ],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout.strip().split('\n')
        snis = [line.strip() for line in output if line.strip()]
        if snis:
            print(f"Detected domain: {snis[-1]}")
            return snis[-1]
        else:
            print("No SNI found.")
            return None
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e.stderr}")
        return None

def get_redirect_chain(start_url):
    try:
        response = requests.get(start_url, allow_redirects=True, timeout=3)

        if not response.history:
            return []

        chain = []
        for resp in response.history:
            loc = resp.headers.get("Location")
            if loc:
                parsed = urlparse(loc)
                domain = parsed.hostname or urlparse(resp.url).hostname
                if domain:
                    chain.append(domain)

        final_domain = urlparse(response.url).hostname
        if final_domain:
            chain.append(final_domain)

        return list(dict.fromkeys(chain))
    except Exception:
        return []

def is_useful_domain(domain):
    return domain and domain.lower() not in EXCLUDE_DOMAINS

def ssl_scan(auto=True, domain_override=None):
    domain = domain_override or get_latest_sni(interface="Wi-Fi", timeout=3)

    if domain and is_useful_domain(domain):
        url = f"https://{domain}"
        redirect_domains = get_redirect_chain(url)

        if not redirect_domains:
            safe = validate_certificate(domain)
            return {
                "status": "safe" if safe else "unsafe",
                "details": f"Direct SSL validation for {domain}: {'Valid' if safe else 'Invalid'} certificate."
            }
        else:
            all_passed = True
            details = ""
            for d in redirect_domains:
                result = validate_certificate(d)
                details += f"{d}: {'Valid' if result else 'Invalid'}\n"
                if not result:
                    all_passed = False
            return {
                "status": "safe" if all_passed else "unsafe",
                "details": f"Redirect chain:\n{details}"
            }
    else:
        return {
            "status": "unsafe",
            "details": "No useful domain detected."
        }

def auto_scan_step(scanned_domains, tshark_path="tshark", interface="Wi-Fi", timeout=3):
    """
    Single step for auto scanning.
    Returns scan result dict for a new domain not scanned yet, or None if no new domain.
    """
    domain = get_latest_sni(tshark_path=tshark_path, interface=interface, timeout=timeout)
    if domain and domain not in scanned_domains and is_useful_domain(domain):
        scanned_domains.add(domain)
        return ssl_scan(domain_override=domain)
    return None

def get_beacon_status():
    # Dummy beacon frame analysis
    return {"status": "suspicious", "details": "Duplicate SSID detected with mismatched BSSID."}
