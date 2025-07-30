# beacon_analyzer.py

import sys
import platform
import subprocess
from scapy.all import * 
from scapy.all import sniff, Dot11, Dot11Elt, conf, RadioTap
import signal
import atexit
from MAC_Vendor_Lookup import lookup_vendor
#from utils import is_suspicious_ap

observed_aps = {}

CHANNEL_FREQ_MAP = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432, 6: 2437, 7: 2442, 8: 2447, 9: 2452,
    10: 2457, 11: 2462, 12: 2467, 13: 2472, 14: 2484,
    36: 5180, 40: 5200, 44: 5220, 48: 5240,
    52: 5260, 56: 5280, 60: 5300, 64: 5320,
    100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640,
    132: 5660, 136: 5680, 140: 5700,
    149: 5745, 153: 5765, 157: 5785, 161: 5805, 165: 5825}

def enable_monitor_mode(interface):
    os_type = platform.system().lower()
    print(f"[*] Enabling monitor mode on {interface} for {os_type}...")

    try:
        if "linux" in os_type:
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["sudo", "iw", interface, "set", "monitor", "none"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        elif "darwin" in os_type:  # macOS
            print("[!] Monitor mode on macOS must be enabled manually or via supported tools (e.g., airport).")
            print("Example: sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en0 sniff 1")
        elif "windows" in os_type:
            print("[!] Windows typically does not support monitor mode via Scapy. Use Linux for full functionality.")
        else:
            print("[!] Unsupported OS. Manual monitor mode activation may be required.")
    except subprocess.CalledProcessError as e:
        print(f"Error enabling monitor mode: {e}")
        sys.exit(1)

def stop_monitor_mode(interface):
    os_type = platform.system().lower()
    print(f"[*] Disabling monitor mode on {interface}...")

    try:
        if "linux" in os_type:
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["sudo", "iw", interface, "set", "type", "managed"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        elif "darwin" in os_type:
            print("[!] On macOS, stop sniffing using Ctrl+C and restart Wi-Fi via GUI if needed.")
    except subprocess.CalledProcessError as e:
        print(f"Error disabling monitor mode: {e}")

global_interface = None


def graceful_exit():
    if global_interface:
        stop_monitor_mode(global_interface)

# Register cleanup on normal exit
atexit.register(graceful_exit)


def get_channel_info(packet):
    channel = None

    if packet.haslayer(Dot11Elt):
        elt = packet[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 3:  # DS Parameter Set
                try:
                    channel = int.from_bytes(elt.info, byteorder='little')
                    break
                except:
                    pass
            elt = elt.payload

    # If channel wasn't found, try to guess based on freq
    freq = None
    if packet.haslayer(RadioTap):
        try:
            freq = packet[RadioTap].ChannelFrequency
            if not channel and freq:
                for ch, f in CHANNEL_FREQ_MAP.items():
                    if f == freq:
                        channel = ch
                        break
        except:
            pass

    return channel or 'Unknown', freq or 'Unknown'
def handle_packet(packet):
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        bssid = packet.addr2
        try:
            ssid = packet.info.decode('utf-8', errors='ignore').strip()
        except:
            ssid = "<Undecodable SSID>"

        channel, freq = get_channel_info(packet)
        vendor = lookup_vendor(bssid)

        if bssid not in observed_aps:
            observed_aps[bssid] = {
                "SSID": ssid,
                "Channel": channel,
                "Frequency": freq,
                "Vendor": vendor
            }
            print(f"Detected AP -> SSID: {ssid or '<Hidden>'}, BSSID: {bssid}, Channel: {channel}, Frequency: {freq} MHz, Vendor: {vendor}")



def signal_handler(sig, frame):
    print("\n[*] Detected Ctrl+C. Cleaning up and exiting...")
    stop_monitor_mode(interface)
    sys.exit(0)


def start_sniffing(interface):
    enable_monitor_mode(interface)
    print("[*] Starting beacon frame analysis using Scapy (monitor mode enabled)...")
    conf.use_pcap = True

    signal.signal(signal.SIGINT, signal_handler)

    try:
        sniff(iface=interface, prn=handle_packet, store=0, monitor=True)
    except Exception as e:
        print(f"[!] Error during sniffing: {e}")
    finally:
        stop_monitor_mode(interface)
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python beacon_analyzer.py <interface>")
        sys.exit(1)
    interface = sys.argv[1]
    start_sniffing(interface)
