from scapy.all import sniff, IP
from detection.port_scan_detector import detect_port_scan

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        print(f"[PACKET] {src} -> {dst}")

        detect_port_scan(packet)

def start_sniffing():
    print("LONGWEI IDS Packet Collector Started...")
    sniff(prn=packet_callback, store=False,iface="eth0")

