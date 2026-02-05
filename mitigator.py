import os
import time
import csv
from scapy.all import sniff, IP
from collections import Counter

# --- Configuration ---
THRESHOLD = 50        # Packets per window
WINDOW_SIZE = 10      # Seconds per window
LOG_FILE = "attack_log.csv"

packet_counts = Counter()
start_time = time.time()
blocked_ips = set()

# Initialize CSV file with headers if it doesn't exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source_IP", "Packet_Count", "Action"])


def log_to_csv(ip, count):
    """Saves the attack data to a CSV file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, ip, count, "BLOCKED"])


def block_ip(ip, count):
    """Blocks the IP via Windows Firewall and logs it."""
    if ip not in blocked_ips:
        print(
            f"\n[!] ALERT: High traffic from {ip} ({count} packets). Blocking...")
        cmd = f'netsh advfirewall firewall add rule name="DDoS_Block_{ip}" dir=in action=block remoteip={ip}'
        os.system(cmd)
        blocked_ips.add(ip)
        log_to_csv(ip, count)


def process_packet(pkt):
    global start_time, packet_counts

    if pkt.haslayer(IP):
        packet_counts[pkt[IP].src] += 1

        # Check window expiry
        if time.time() - start_time > WINDOW_SIZE:
            print(f"\n--- Traffic Report ({time.strftime('%H:%M:%S')}) ---")
            print(f"{'Source IP':<20} | {'Packets':<10}")
            print("-" * 35)

            if not packet_counts:
                print("No traffic detected.")

            for ip, count in packet_counts.items():
                print(f"{ip:<20} | {count:<10}")
                if count > THRESHOLD:
                    block_ip(ip, count)

            # Reset
            packet_counts.clear()
            start_time = time.time()


print(f"Monitoring... Logs will be saved to {LOG_FILE}")
sniff(filter="ip", prn=process_packet, store=0)
