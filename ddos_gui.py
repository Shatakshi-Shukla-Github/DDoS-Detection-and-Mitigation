# import os
# import time
# import csv
# import threading
# import tkinter as tk
# from tkinter import ttk, scrolledtext
# from scapy.all import sniff, IP, conf, get_if_list
# from collections import Counter


# class DDoSGuardian:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("🛡️ GUARDIAN - Active Defense")
#         self.root.geometry("850x600")
#         self.root.configure(bg="#1a1a1a")

#         self.threshold = 50
#         self.packet_counts = Counter()
#         self.is_monitoring = False
#         self.log_file = "attack_history.csv"

#         # Initialize CSV
#         if not os.path.exists(self.log_file):
#             with open(self.log_file, 'w', newline='') as f:
#                 writer = csv.writer(f)
#                 writer.writerow(["Timestamp", "IP", "PacketCount", "Status"])

#         self.setup_ui()
#         self.write_log("System Ready. Mobile/WiFi support active.")

#     def setup_ui(self):
#         tk.Label(self.root, text="DDoS DEFENSE CONSOLE", font=(
#             "Consolas", 18, "bold"), fg="#00ffcc", bg="#1a1a1a").pack(pady=10)

#         self.tree = ttk.Treeview(self.root, columns=(
#             "IP", "Count", "Status"), show='headings')
#         self.tree.heading("IP", text="Source IP Address")
#         self.tree.heading("Count", text="Packets (Last 5s)")
#         self.tree.heading("Status", text="Security Status")
#         self.tree.pack(pady=10, padx=20, fill="x")

#         self.log_area = scrolledtext.ScrolledText(
#             self.root, height=12, bg="black", fg="#00ff00", font=("Consolas", 10))
#         self.log_area.pack(pady=10, padx=20, fill="both")

#         btn_frame = tk.Frame(self.root, bg="#1a1a1a")
#         btn_frame.pack(pady=10)

#         self.start_btn = tk.Button(btn_frame, text="▶ START DEFENSE", command=self.start_thread,
#                                    bg="#28a745", fg="white", width=20, font=("Arial", 10, "bold"))
#         self.start_btn.pack(side="left", padx=5)

#         tk.Button(btn_frame, text="🧹 CLEAN FIREWALL", command=self.run_cleanup,
#                   bg="#dc3545", fg="white", width=20).pack(side="left", padx=5)

#     def write_log(self, msg):
#         self.log_area.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
#         self.log_area.see(tk.END)

#     def log_attack(self, ip, count):
#         with open(self.log_file, 'a', newline='') as f:
#             writer = csv.writer(f)
#             writer.writerow(
#                 [time.strftime('%Y-%m-%d %H:%M:%S'), ip, count, "BLOCKED"])

#     def run_cleanup(self):
#         # Cleans rules via PowerShell silently
#         os.system(
#             'PowerShell "Get-NetFirewallRule -DisplayName \'DDoS_Block_*\' | Remove-NetFirewallRule"')
#         self.write_log("Cleanup: All firewall block rules removed.")

#     def update_table(self, data):
#         for item in self.tree.get_children():
#             self.tree.delete(item)

#         for ip, count in sorted(data.items(), key=lambda x: x[1], reverse=True):
#             status = "🟢 CLEAN"
#             if count > self.threshold:
#                 status = "🚨 BLOCKED"
#                 os.system(
#                     f'netsh advfirewall firewall add rule name="DDoS_Block_{ip}" dir=in action=block remoteip={ip}')
#                 self.log_attack(ip, count)

#             self.tree.insert("", "end", values=(ip, count, status))

#     def monitor_loop(self):
#         self.is_monitoring = True
#         self.write_log(f"Monitoring ALL interfaces...")

#         while self.is_monitoring:
#             try:
#                 self.packet_counts.clear()
#                 # timeout=5 captures traffic for 5 seconds
#                 # store=0 keeps memory usage low
#                 sniff(filter="ip", prn=lambda x: self.packet_counts.update(
#                     [x[IP].src]) if x.haslayer(IP) else None, timeout=5, store=0)

#                 current_stats = dict(self.packet_counts)
#                 self.root.after(0, self.update_table, current_stats)
#             except Exception as e:
#                 self.root.after(0, self.write_log, f"Error: {e}")
#                 break

#     def start_thread(self):
#         self.start_btn.config(state="disabled", text="🛡️ DEFENDING")
#         threading.Thread(target=self.monitor_loop, daemon=True).start()


# if __name__ == "__main__":
#     root = tk.Tk()
#     app = DDoSGuardian(root)
#     root.mainloop()







import os
import time
import csv
import threading
import json
import tkinter as tk
from tkinter import ttk, scrolledtext
from urllib.request import urlopen
from scapy.all import sniff, IP
from collections import Counter


class DDoSGuardian:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ GUARDIAN - Active Defense + Geo-Location")
        self.root.geometry("950x650")
        self.root.configure(bg="#1a1a1a")

        # --- Settings ---
        self.threshold = 50
        self.packet_counts = Counter()
        self.is_monitoring = False
        self.log_file = "attack_history.csv"
        self.geo_cache = {}  # Stores IP: "City, Country" to save bandwidth

        # Initialize CSV
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["Timestamp", "IP", "Location", "PacketCount", "Status"])

        self.setup_ui()
        self.write_log("System Ready. Geo-Location Engine Active.")

    def get_location(self, ip):
        """Fetches City, Country for an IP using a free API with caching."""
        if ip in self.geo_cache:
            return self.geo_cache[ip]

        # Identify local/internal traffic
        if ip.startswith(("192.", "127.", "10.", "172.16.")):
            return "Internal Network"

        try:
            # Using built-in urllib for zero dependencies
            url = f"http://ip-api.com/json/{ip}"
            with urlopen(url, timeout=1) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success':
                    loc = f"{data.get('city')}, {data.get('countryCode')}"
                else:
                    loc = "Unknown Source"
        except:
            loc = "Lookup Failed"

        self.geo_cache[ip] = loc  # Save to cache
        return loc

    def setup_ui(self):
        tk.Label(self.root, text="DDoS DEFENSE CONSOLE", font=("Consolas", 18, "bold"),
                 fg="#00ffcc", bg="#1a1a1a").pack(pady=10)

        # Added "Location" to the columns list
        self.tree = ttk.Treeview(self.root, columns=(
            "IP", "Count", "Location", "Status"), show='headings')
        self.tree.heading("IP", text="Source IP Address")
        self.tree.heading("Count", text="Packets (Last 5s)")
        self.tree.heading("Location", text="Origin (City, Country)")
        self.tree.heading("Status", text="Security Status")

        # Set column widths
        self.tree.column("IP", width=150)
        self.tree.column("Count", width=100)
        self.tree.column("Location", width=200)
        self.tree.column("Status", width=150)
        self.tree.pack(pady=10, padx=20, fill="x")

        self.log_area = scrolledtext.ScrolledText(
            self.root, height=12, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(pady=10, padx=20, fill="both")

        btn_frame = tk.Frame(self.root, bg="#1a1a1a")
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text="▶ START DEFENSE", command=self.start_thread,
                                   bg="#28a745", fg="white", width=22, font=("Arial", 10, "bold"))
        self.start_btn.pack(side="left", padx=5)

        tk.Button(btn_frame, text="🧹 CLEAN FIREWALL", command=self.run_cleanup,
                  bg="#dc3545", fg="white", width=22, font=("Arial", 10)).pack(side="left", padx=5)

    def write_log(self, msg):
        self.log_area.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_area.see(tk.END)

    def log_attack(self, ip, location, count):
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'),
                            ip, location, count, "BLOCKED"])

    def run_cleanup(self):
        os.system(
            'PowerShell "Get-NetFirewallRule -DisplayName \'DDoS_Block_*\' | Remove-NetFirewallRule"')
        self.write_log("Cleanup: All firewall block rules removed.")

    def update_table(self, data):
        # Clear existing rows
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Populate with new data
        for ip, count in sorted(data.items(), key=lambda x: x[1], reverse=True):
            location = self.get_location(ip)  # Fetch Geo Data
            status = "🟢 CLEAN"

            if count > self.threshold:
                status = "🚨 BLOCKED"
                # Windows Firewall Block
                os.system(
                    f'netsh advfirewall firewall add rule name="DDoS_Block_{ip}" dir=in action=block remoteip={ip}')
                self.log_attack(ip, location, count)
                self.write_log(f"ALERT: Blocked {ip} from {location}")

            self.tree.insert("", "end", values=(ip, count, location, status))

    def monitor_loop(self):
        self.is_monitoring = True
        self.write_log("Guardian Mode: Live Sniffing & Geo-Tracking Active...")

        while self.is_monitoring:
            try:
                self.packet_counts.clear()
                # Capture for 5 seconds per snapshot
                sniff(filter="ip", prn=lambda x: self.packet_counts.update([x[IP].src]) if x.haslayer(IP) else None,
                      timeout=5, store=0)

                current_stats = dict(self.packet_counts)
                # Update GUI safely
                self.root.after(0, self.update_table, current_stats)
            except Exception as e:
                self.root.after(0, self.write_log, f"Capture Error: {e}")
                break

    def start_thread(self):
        self.start_btn.config(state="disabled", text="🛡️ DEFENDING...")
        threading.Thread(target=self.monitor_loop, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSGuardian(root)
    root.mainloop()
