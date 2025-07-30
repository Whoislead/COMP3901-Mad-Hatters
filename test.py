import sys
import platform
import subprocess
from scapy.all import sniff, Dot11, Dot11Elt, conf
from MAC_Vendor_Lookup import lookup_vendor  # still included
# from utils import is_suspicious_ap

observed_aps = {}

def enable_monitor_mode(interface):
    os_type = platform.system().lower()
    print(f"[*] Enabling monitor mode on {interface} for {os_type}...")

    try:
        if "linux" in os_type:
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["sudo", "iw", interface, "set", "monitor", "none"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        elif "darwin" in os_type:
            print("[!] Monitor mode on macOS must be enabled manually or via supported tools (e.g., airport).")
            print("Example: sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en0 sniff 1")
        elif "windows" in os_type:
            print("[!] Windows typically does not support monitor mode via Scapy. Use Linux for full functionality.")
        else:
            print("[!] Unsupported OS. Manual monitor mode activation may be required.")
    except subprocess.CalledProcessError as e:
        print(f"Error enabling monitor mode: {e}")
        sys.exit(1)

def get_channel(packet):
    if packet.haslayer(Dot11Elt):
        elt = packet[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 3:  # DS Parameter Set
                return int.from_bytes(elt.info, byteorder='little')
            elt = elt.payload
    return 'Unknown'

def get_channel_frequency(packet):
    # Extract frequency from RadioTap layer (if available)
    if hasattr(packet, 'ChannelFrequency'):
        return packet.ChannelFrequency
    elif hasattr(packet, 'SC'):  # fallback
        return packet.SC
    else:
        return 'Unknown'

def get_vendor_specific_tags(packet):
    vendor_tags = []
    if packet.haslayer(Dot11Elt):
        elt = packet[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 221:  # Vendor Specific Tag
                oui_bytes = elt.info[:3]
                try:
                    oui = ':'.join(f"{b:02x}" for b in oui_bytes).upper()
                    vendor_name = resolve_vendor_name_from_oui(oui)
                    if vendor_name:
                        vendor_tags.append(vendor_name)
                    else:
                        vendor_tags.append(f"Vendor OUI: {oui}")
                except Exception:
                    vendor_tags.append("Malformed Vendor Tag")
            elt = elt.payload
    return list(set(vendor_tags)) if vendor_tags else ['None']

def resolve_vendor_name_from_oui(oui):
    vendor_map = {
        "00:40:96": "Cisco Systems",
        "00:14:BF": "Cisco Systems",
        "00:05:9A": "Cisco Systems",
        "00:0B:86": "Cisco Meraki",
        "00:17:C5": "Apple, Inc.",
        "00:18:0A": "Aruba Networks",
        "00:0F:66": "Netgear",
        "00:13:02": "Intel",
        "00:1A:1E": "Aironet (Cisco)",
        # You can expand this list or auto-load from IEEE database
    }
    return vendor_map.get(oui)

def handle_packet(packet):
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        bssid = packet.addr2
        ssid = packet.info.decode(errors='ignore')
        channel = get_channel(packet)
        channel_freq = get_channel_frequency(packet)
        vendor_mac_lookup = lookup_vendor(bssid)
        vendor_tags = get_vendor_specific_tags(packet)

        if bssid not in observed_aps:
            observed_aps[bssid] = {
                "SSID": ssid,
                "Channel": channel,
                "Channel Frequency": channel_freq,
                "Vendor (MAC Lookup)": vendor_mac_lookup,
                "Vendor Tags (Broadcast)": vendor_tags
            }

            print(f"\nDetected AP -> SSID: {ssid}")
            print(f"  BSSID: {bssid}")
            print(f"  Channel: {channel}")
            print(f"  Channel Frequency: {channel_freq} MHz")
            print(f"  Vendor (MAC Lookup): {vendor_mac_lookup}")
            print(f"  Vendor Tags (Broadcast): {', '.join(vendor_tags)}")

            # if is_suspicious_ap(ssid, bssid, channel, vendor_mac_lookup):
            #     print("⚠️ Potential Evil Twin detected!")

def start_sniffing(interface):
    enable_monitor_mode(interface)
    print("[*] Starting beacon frame analysis using Scapy (monitor mode enabled)...")
    conf.use_pcap = True
    sniff(iface=interface, prn=handle_packet, store=0, monitor=True)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test.py <interface>")
        sys.exit(1)
    interface = sys.argv[1]
    start_sniffing(interface)
