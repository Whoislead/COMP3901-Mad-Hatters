import Beacon_frame_analyzer
import MAC_Vendor_Lookup
import SSL_Cert_Check
import WigleAPI
import ShodanAPI

def main():
    print("Welcome to the Evil Twin Checker App!")
    print("Please select an option to proceed:")

    print("1. Scan Networks for Beacon Frames")
    print("2. Run SSL Certificate + Redirect Check")
    print("3. Query Wigle API for possible locations")
    print("4. Query Shodan API")
    
    choice = input("Select an option (1-4): ")
    
    if choice == '1':
        interface = input("Enter network interface for beacon analysis: ")
        Beacon_frame_analyzer.start_sniffing(interface)
    elif choice == '2':
        mode = input("Auto detect domain from traffic? (y/n): ").strip().lower()
        if mode == 'y':
            result = SSL_Cert_Check.ssl_scan(auto=True)
        else:
            domain = input("Enter domain to scan (e.g. google.com): ").strip()
            result = SSL_Cert_Check.ssl_scan(auto=False, domain_override=domain)
        print(f"\nScan Status: {result['status'].upper()}")
        print("Details:")
        print(result["details"])
    elif choice == '3':
        WigleAPI.query_wigle_api()
    elif choice == '4':
        ShodanAPI.query_shodan_api()
    else:
        print("Invalid option selected.")


if __name__ == "__main__":
    main()