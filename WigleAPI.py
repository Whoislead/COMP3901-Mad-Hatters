# wigle_lookup.py
import requests
from requests.auth import HTTPBasicAuth

def wigle_check(bssid=None, ssid=None):
    url = "https://api.wigle.net/api/v2/network/search"
    params = {}
    if bssid:
        params['netid'] = bssid
    if ssid:
        params['ssid'] = ssid

    auth = HTTPBasicAuth("AID353e1b45a21270feb01d6319058a0d6b", "92016658087d849231db3a1d2c4f1870")

    try:
        resp = requests.get(url, params=params, auth=auth)
        resp.raise_for_status()  # Will raise HTTPError for bad status
        data = resp.json()
        if data.get('totalResults', 0) > 0:
            return data['results']
        else:
            return None
    except requests.exceptions.RequestException as e:
        print("Error contacting Wigle API:", e)
        return None

def get_field(data, key):
    return data.get(key, "Not Available")

if __name__ == "__main__":
    print("Search Wigle by:")
    print("1. BSSID")
    print("2. SSID")
    print("3. Both")

    choice = input("Enter choice (1/2/3): ").strip()

    bssid = None
    ssid = None

    if choice == '1':
        bssid = input("Enter BSSID: ").strip()
    elif choice == '2':
        ssid = input("Enter SSID: ").strip()
    elif choice == '3':
        bssid = input("Enter BSSID: ").strip()
        ssid = input("Enter SSID: ").strip()
    else:
        print("Invalid choice.")
        exit(1)

    results = wigle_check(bssid=bssid, ssid=ssid)
    if results:
        print(f"\nFound {len(results)} result(s):")
        for res in results:
            print(f"\n--- Access Point ---")
            print(f"SSID: {get_field(res, 'ssid')}")
            print(f"BSSID: {get_field(res, 'netid')}")
            print(f"Channel: {get_field(res, 'channel')}")
            print(f"Frequency: {get_field(res, 'frequency')}")
            print(f"Location Coordinates: ({get_field(res, 'trilat')}, {get_field(res, 'trilong')})")
            print(f"First Seen: {get_field(res, 'firsttime')}")
            print(f"Last Seen: {get_field(res, 'lasttime')}")
            print(f"Last Updated: {get_field(res, 'lastupdt')}")
            print(f"Encryption: {get_field(res, 'encryption')}")
            print(f"RCOIS: {get_field(res, 'rcois')}")
            print(f"Country: {get_field(res, 'country')}")
            print(f"Region: {get_field(res, 'region')}")
            print(f"Road: {get_field(res, 'road')}")
            print(f"City: {get_field(res, 'city')}")
            print(f"House Number: {get_field(res, 'housenumber')}")
            print(f"Postal Code: {get_field(res, 'postalcode')}")
    else:
        print("\nNo record found. This AP may be rogue or not indexed yet.")
