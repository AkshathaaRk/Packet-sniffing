import threading
import time
from scapy.all import sniff, IP, wrpcap, send, ARP
from collections import Counter
from datetime import datetime

# Global variables
captured_packets = []
protocol_count = Counter()
alerted_ips = set()
PACKET_FILE = "sniff.txt"  # Text file to save packet details
SUSPICIOUS_IPS = ["ENTER THE TARGET IP"]  # Example of IPs to monitor
packet_lock = threading.Lock()

# Packet processing function
def process_packet(packet):
    global protocol_count

    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        protocol = ip_layer.proto

        # Increment protocol count
        with packet_lock:
            protocol_count[protocol] += 1
            captured_packets.append(packet)

            # Append packet info to text file
            try:
                with open(PACKET_FILE, "a") as file:
                    file.write(f"[{datetime.now()}] Src: {src}, Dst: {dst}, Protocol: {protocol}\n")
            except IOError as e:
                print(f"Error writing to file: {e}")

        # Display packet info
        print(f"[{datetime.now()}] Src: {src}, Dst: {dst}, Protocol: {protocol}")

        # Alert for suspicious IPs
        if src in SUSPICIOUS_IPS or dst in SUSPICIOUS_IPS:
            if src not in alerted_ips:
                print(f"ALERT: Traffic from/to suspicious IP {src} detected!")
                alerted_ips.add(src)

# Inject custom packets (e.g., ARP spoofing)
def inject_packets():
    while True:
        try:
            print("Injecting ARP spoofing packets...")
            packet = ARP(op=2, pdst="192.168.1.101", hwdst="ff:ff:ff:ff:ff:ff")
            send(packet, verbose=False)
            print("Packet injected.")
        except Exception as e:
            print(f"Error injecting packet: {e}")
        time.sleep(20)

# Display real-time network statistics
def display_statistics():
    while True:
        time.sleep(5)
        with packet_lock:
            print(f"\n[{datetime.now()}] Real-Time Network Statistics:")
            for proto, count in protocol_count.items():
                print(f"Protocol {proto}: {count} packets")
            print(f"Total Packets Captured: {len(captured_packets)}\n")

# Start sniffing packets
def start_sniffing():
    print("Starting packet sniffing...")
    try:
        sniff(filter="ip", prn=process_packet, store=False)
    except Exception as e:
        print(f"Error during sniffing: {e}")

# Main function
if __name__ == "__main__":
    # Clear existing file content at start
    try:
        with open(PACKET_FILE, "w") as file:
            file.write("Packet Sniffing Log:\n\n")
    except IOError as e:
        print(f"Error initializing log file: {e}")
        exit(1)

    # Start threads for different features
    threading.Thread(target=display_statistics, daemon=True).start()
    threading.Thread(target=inject_packets, daemon=True).start()

    # Start packet sniffing
    start_sniffing()