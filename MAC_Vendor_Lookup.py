#This lookup relies on an AP havnig a Non rotating Mac Address
# The first few bytes (OUI) of the MAC address, which indicate the manufacturer, are randomized along with the rest of the address if it is a rotating MAC address.
# This script will not be able to identify the vendor of such an AP.
#To attempt in countering this, we use the Tag Vendor Specific information picked up in the beacon frame.
import requests
import re
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

def lookup_macvendors_api(mac):
    try:
        oui = ":".join(mac.split(":")[:3]).upper()
        resp = requests.get(f"https://api.macvendors.com/{oui}", timeout=5)
        if resp.status_code == 200 and "errors" not in resp.text.lower():
            return resp.text.strip()
    except:
        pass
    return None

def lookup_macaddressio(mac):
    try:
        oui = mac.upper().replace(":", "-")
        url = f"https://macaddress.io/mac-address-lookup/{oui}"
        resp = requests.get(url, headers=HEADERS, timeout=6)
        if resp.status_code == 200:
            match = re.search(r"Vendor:\s*</span>\s*(.*?)\s*</div>", resp.text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    except:
        pass
    return None

def lookup_wireshark(mac):
    try:
        oui = "".join(mac.split(":")[:3]).upper()
        url = f"https://www.wireshark.org/tools/oui-lookup.html"
        resp = requests.get(url, params={"field": oui}, headers=HEADERS, timeout=6)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            pre = soup.find("pre")
            if pre and oui in pre.text:
                lines = pre.text.strip().split("\n")
                for line in lines:
                    if oui in line:
                        return line.split(oui)[-1].strip()
    except:
        pass
    return None

def lookup_vendor(mac):
    """
    Checks 3 sources for MAC vendor lookup.
    Returns the first successful match or 'Unknown Vendor'.
    """
    methods = [
        lookup_macvendors_api,
        lookup_macaddressio,
        lookup_wireshark,
    ]
    for method in methods:
        result = method(mac)
        if result:
            return result
    return "Unknown Vendor"

if __name__ == "__main__":
    test_mac = input("Enter MAC address (BSSID): ")
    print("Vendor:", lookup_vendor(test_mac))
