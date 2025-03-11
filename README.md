# Network Packet Sniffer & Injector

## Overview
This Python script captures network packets, logs them, and detects suspicious IPs. It also injects ARP spoofing packets and provides real-time network statistics.

## Features
- Captures IP packets and logs details.
- Monitors traffic for suspicious IPs.
- Injects ARP spoofing packets.
- Displays real-time network statistics.

## Requirements
- Python 3.x
- Required libraries:
  - scapy
  - threading
  - collections
  - datetime
  - time

Install dependencies using:
bash
pip install scapy


## Usage
Run the script with:
bash
python script.py


## Configuration
- *SUSPICIOUS_IPS*: Modify this list to add IPs to monitor.
- *PACKET_FILE*: Change the filename to store captured packets.

## Functions
- process_packet(packet): Captures and logs packet details.
- inject_packets(): Sends ARP spoofing packets every 20 seconds.
- display_statistics(): Displays protocol statistics every 5 seconds.
- start_sniffing(): Begins sniffing network packets.

## Notes
- Run with administrative/root privileges for full functionality.
- Modify the ARP injection target as needed.

## Disclaimer
Use this script responsibly and only on networks you have permission to monitor and modify.
