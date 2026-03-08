from collections import defaultdict
import time
import os
import json

scan_tracker = defaultdict(list)
alert_tracker={}
ALERT_COOLDOWN=30

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

           now = time.time()

           if src not in alert_tracker or now - alert_tracker[src] > ALERT_COOLDOWN:

              alert_tracker[src] = now

              alert = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "attacker_ip": src,
                "event": "Port Scan Detected"
              }

              print(f"[ALERT] Possible port scan from {src}")

              with open("logs/alerts.log", "a") as f:
               f.write(json.dumps(alert) + "\n")

              os.system(f"sudo iptables -A INPUT -s {src} -j DROP")
              print(f"[DEFENSE] Blocked IP {src}")
