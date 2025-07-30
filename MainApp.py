import Beacon_frame_analyzer
import MAC_Vendor_Lookup
import SSL_Cert_Check
import WigleAPI
import ShodanAPI

def main():
    print("Welcome to the Evil Twin Checker App!")
    print("Please select an option to proceed:")

    print("1. To scan Networks for Beacon Frames")
    print("2. To Check SSL Certificates")
    print("3. To Query Wigle API for possible locations")
    print("4. To Query Shodan API")
    
    choice = input("Select an option (1-4): ")
    
    if choice == '1':
        interface = input("Enter network interface for beacon analysis: ")
        Beacon_frame_analyzer.start_sniffing(interface)
    elif choice == '2':
        domain = input("Enter domain to check SSL certificate: ")
        SSL_Cert_Check.check_ssl_cert(domain)
    elif choice == '3':
        WigleAPI.query_wigle_api()
    elif choice == '4':
        ShodanAPI.query_shodan_api()
    else:
        print("Invalid option selected.")


if __name__ == "__main__":
    main()