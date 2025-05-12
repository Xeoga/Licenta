from collections import defaultdict
from datetime import datetime, timedelta
import re
import json
import os

class Detector:
    def __init__(self, log_folder="log"):
        self.port_access = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.syn_flags = defaultdict(list)
        self.icmp_flood = defaultdict(list)
        self.udp_flood = defaultdict(list)
        self.arp_activity = defaultdict(list)
        self.BLACKLIST = {"1.2.3.4", "198.51.100.23"}
        self.log_folder = log_folder
        self.ensure_log_folder_exists()

    def ensure_log_folder_exists(self):
        os.makedirs(self.log_folder, exist_ok=True)

    def log_alert(self, alert_msg, alert_level):
        today_str = datetime.now().strftime("%Y-%m-%d")
        log_filename = os.path.join(self.log_folder, f"{today_str}.log")
        json_filename = os.path.join(self.log_folder, f"{today_str}.json")

        timestamp = datetime.now().isoformat()

        # Scriere în fișierul log
        with open(log_filename, "a") as log_file:
            log_file.write(f"[{timestamp}] [{alert_level}] {alert_msg}\n")

        # Salvare în fișierul JSON
        alert_data = {"timestamp": timestamp, "level": alert_level, "message": alert_msg}
        if os.path.exists(json_filename):
            with open(json_filename, "r+") as json_file:
                try:
                    data = json.load(json_file)
                except json.JSONDecodeError:
                    data = []
                data.append(alert_data)
                json_file.seek(0)
                json.dump(data, json_file, indent=4)
        else:
            with open(json_filename, "w") as json_file:
                json.dump([alert_data], json_file, indent=4)

    def process_packet(self, line):
        alerts = []
        now = datetime.now()

        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        port_match = re.search(r"port\s+(\d+)", line, re.IGNORECASE)
        if not ip_match:
            return []

        src_ip = ip_match.group(1)
        dst_port = int(port_match.group(1)) if port_match else None

        # 0. Blacklist
        if src_ip in self.BLACKLIST:
            msg = f"Trafic de la IP aflat în blacklist: {src_ip}"
            self.log_alert(msg, "CRITICAL")
            alerts.append((msg, "CRITICAL"))

        # 1. Port Scan Detection
        if dst_port:
            self.port_access[src_ip].append((dst_port, now))
            self.port_access[src_ip] = [
                (p, t) for p, t in self.port_access[src_ip] if now - t < timedelta(seconds=10)
            ]
            distinct_ports = {p for p, _ in self.port_access[src_ip]}
            if len(distinct_ports) > 10:
                msg = f"Port scan detectat de la {src_ip}"
                self.log_alert(msg, "CRITICAL")
                alerts.append((msg, "CRITICAL"))

        # 2. DNS Flood Detection
        if "udp" in line.lower() and "53" in line:
            self.dns_queries[src_ip].append(now)
            self.dns_queries[src_ip] = [
                t for t in self.dns_queries[src_ip] if now - t < timedelta(seconds=5)
            ]
            if len(self.dns_queries[src_ip]) > 10:
                msg = f"DNS flood suspect de la {src_ip}"
                self.log_alert(msg, "WARN")
                alerts.append((msg, "WARN"))

        # 3. SYN Flood
        if "SYN" in line and "ACK" not in line:
            self.syn_flags[src_ip].append(now)
            self.syn_flags[src_ip] = [
                t for t in self.syn_flags[src_ip] if now - t < timedelta(seconds=5)
            ]
            if len(self.syn_flags[src_ip]) > 15:
                msg = f"Posibil SYN flood de la {src_ip}"
                self.log_alert(msg, "WARN")
                alerts.append((msg, "WARN"))

        # 4. ICMP Flood
        if "ICMP" in line:
            self.icmp_flood[src_ip].append(now)
            self.icmp_flood[src_ip] = [
                t for t in self.icmp_flood[src_ip] if now - t < timedelta(seconds=5)
            ]
            if len(self.icmp_flood[src_ip]) > 10:
                msg = f"ICMP flood detectat de la {src_ip}"
                self.log_alert(msg, "INFO")
                alerts.append((msg, "INFO"))

        # 5. UDP Flood
        if "UDP" in line:
            self.udp_flood[src_ip].append(now)
            self.udp_flood[src_ip] = [
                t for t in self.udp_flood[src_ip] if now - t < timedelta(seconds=5)
            ]
            if len(self.udp_flood[src_ip]) > 20:
                msg = f"Posibil UDP flood de la {src_ip}"
                self.log_alert(msg, "WARN")
                alerts.append((msg, "WARN"))

        # 6. ARP Spoofing
        if "ARP" in line.upper():
            self.arp_activity[src_ip].append(now)
            self.arp_activity[src_ip] = [
                t for t in self.arp_activity[src_ip] if now - t < timedelta(seconds=10)
            ]
            if len(self.arp_activity[src_ip]) > 5:
                msg = f"Activitate ARP suspectă de la {src_ip}"
                self.log_alert(msg, "INFO")
                alerts.append((msg, "INFO"))

        return alerts
