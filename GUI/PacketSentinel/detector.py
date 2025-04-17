from collections import defaultdict
from datetime import datetime, timedelta
import re

class Detector:
    def __init__(self):
        self.port_access = defaultdict(list)       # ip -> listă de (port, timestamp)
        self.dns_queries = defaultdict(list)       # ip -> listă de timestampuri
        self.syn_flags = defaultdict(list)         # ip -> listă de timestampuri

    def process_packet(self, line):
        alerts = []
        now = datetime.now()

        # Extrage IP sursă și port destinație din linia brută
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        port_match = re.search(r"port\s+(\d+)", line, re.IGNORECASE)
        if not ip_match:
            return []

        src_ip = ip_match.group(1)
        dst_port = int(port_match.group(1)) if port_match else None

        # 1. Port Scan Detection
        if dst_port:
            self.port_access[src_ip].append((dst_port, now))
            self.port_access[src_ip] = [
                (p, t) for p, t in self.port_access[src_ip] if now - t < timedelta(seconds=10)
            ]
            distinct_ports = {p for p, _ in self.port_access[src_ip]}
            if len(distinct_ports) > 10:
                alerts.append(("Port scan detectat de la " + src_ip, "CRITICAL"))

        # 2. DNS Flood Detection (udp port 53)
        if "udp" in line.lower() and "53" in line:
            self.dns_queries[src_ip].append(now)
            self.dns_queries[src_ip] = [
                t for t in self.dns_queries[src_ip] if now - t < timedelta(seconds=5)
            ]
            if len(self.dns_queries[src_ip]) > 10:
                alerts.append(("DNS flood suspect de la " + src_ip, "WARN"))

        # 3. SYN Flood (doar dacă apare "SYN")
        if "SYN" in line and "ACK" not in line:
            self.syn_flags[src_ip].append(now)
            self.syn_flags[src_ip] = [
                t for t in self.syn_flags[src_ip] if now - t < timedelta(seconds=5)
            ]
            if len(self.syn_flags[src_ip]) > 15:
                alerts.append(("Posibil SYN flood de la " + src_ip, "WARN"))

        return alerts
