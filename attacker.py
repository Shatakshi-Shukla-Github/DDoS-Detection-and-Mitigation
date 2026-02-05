from scapy.all import IP, TCP, send
import time

# --- Configuration ---
TARGET_IP = "127.0.0.1"  # Your own machine
TARGET_PORT = 80         # A common port
PACKET_COUNT = 200       # How many packets to send

print(f"Starting simulated attack on {TARGET_IP}...")

# Create a basic packet
packet = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="S")

# Send packets rapidly in a loop
for i in range(PACKET_COUNT):
    send(packet, verbose=False)
    if i % 10 == 0:
        print(f"Sent {i} packets...")

print("Attack simulation complete.")
