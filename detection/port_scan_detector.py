from collections import defaultdict
import time

scan_tracker = defaultdict(list)

def detect_port_scan(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src = packet["IP"].src
        dst_port = packet["TCP"].dport

        scan_tracker[src].append((dst_port, time.time()))

        # keep last 10 seconds
        scan_tracker[src] = [
            (port, t) for port, t in scan_tracker[src]
            if time.time() - t < 10
        ]

        unique_ports = {port for port, _ in scan_tracker[src]}

        if len(unique_ports) > 3:
            print(f"[ALERT] Possible port scan from {src}")

