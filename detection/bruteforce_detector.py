from collections import defaultdict
import time

login_tracker = defaultdict(list)

WINDOW = 20
THRESHOLD = 5

def detect_bruteforce(packet):

    if packet.haslayer("IP") and packet.haslayer("TCP"):

        src = packet["IP"].src
        dst_port = packet["TCP"].dport

        if dst_port == 22:

            login_tracker[src].append(time.time())

            login_tracker[src] = [
                t for t in login_tracker[src]
                if time.time() - t < WINDOW
            ]

            if len(login_tracker[src]) > THRESHOLD:
                print(f"[ALERT] Possible SSH brute force from {src}")
