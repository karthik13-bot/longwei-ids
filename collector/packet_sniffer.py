from scapy.all import sniff, IP

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"[PACKET] {src} -> {dst}")

def start_sniffing():
    print("LONGWEI IDS Packet Collector Started...")
    sniff(prn=packet_callback, store=False)
