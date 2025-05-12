from scapy.all import sniff, wrpcap
import datetime
import re
from collections import defaultdict
from report_generate import ReportData


class TrafficAnalyzerCore:
    def __init__(self):
        self.stop_sniff = False
        self.captured_packets = []
        self.tcp_count = 0
        self.udp_count = 0
        self.other_count = 0
        self.report_data = ReportData()
        self.report_data.connections = defaultdict(set)  # ✅ conexiuni unice

    def start_capture(self, iface, callback, bpf_filter=None):
        self.stop_sniff = False
        sniff(
            iface=iface,
            prn=lambda pkt: self._handle_packet(pkt, callback),
            stop_filter=lambda x: self.stop_sniff,
            filter=bpf_filter if bpf_filter else None
        )

    def stop_capture(self):
        self.stop_sniff = True
        self.finalize_report_data()

    def _handle_packet(self, packet, callback):
        self.captured_packets.append(packet)
        callback(self.format_packet(packet))

        now = datetime.datetime.now()
        if not self.report_data.start_time:
            self.report_data.start_time = now
        self.report_data.end_time = now
        self.report_data.total_packets += 1

        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            self.report_data.sources[src_ip] += 1
            self.report_data.destinations[dst_ip] += 1

            if src_ip != dst_ip:
                self.report_data.connections[src_ip].add(dst_ip)  # ✅ conexiune unică

            proto = self.detect_application_protocol(packet)
            self.report_data.protocols[proto] += 1

        elif packet.haslayer("ARP"):
            self.report_data.protocols["ARP"] += 1

        elif packet.haslayer("ICMP"):
            self.report_data.protocols["ICMP"] += 1

        minute_key = now.strftime("%H:%M")
        self.report_data.packets_per_minute[minute_key] += 1

    def format_packet(self, packet):
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            length = len(packet)
            index = len(self.captured_packets)

            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                protocol = self.detect_application_protocol(packet)
                info = ""

                if packet.haslayer("TCP"):
                    sport = packet["TCP"].sport
                    dport = packet["TCP"].dport
                    info = f"{sport} → {dport} [TCP]"
                elif packet.haslayer("UDP"):
                    sport = packet["UDP"].sport
                    dport = packet["UDP"].dport
                    info = f"{sport} → {dport} [UDP]"
                else:
                    info = f"[IP Proto: {packet['IP'].proto}]"

                return f"{index:<5} {timestamp:<15} {src_ip:<18} {dst_ip:<18} {protocol:<8} {length:<7} {info}\n"

            elif packet.haslayer("ARP"):
                proto = "ARP"
                summary = packet.summary()
                return f"{index:<5} {timestamp:<15} {'-':<18} {'-':<18} {proto:<8} {length:<7} {summary}\n"

            elif packet.haslayer("ICMP"):
                proto = "ICMP"
                summary = packet.summary()
                return f"{index:<5} {timestamp:<15} {'-':<18} {'-':<18} {proto:<8} {length:<7} {summary}\n"

            else:
                summary = packet.summary()
                match = re.search(r'([A-Z]+)', summary)
                proto = match.group(1) if match else "OTHER"
                return f"{index:<5} {timestamp:<15} {'-':<18} {'-':<18} {proto:<8} {length:<7} {summary}\n"

        except Exception as e:
            return f"[Eroare la parsare: {e}]\n"

    def detect_application_protocol(self, packet):
        try:
            port_map = {
                80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 23: "TELNET",
                25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP", 445: "SMB",
                3306: "MySQL", 3389: "RDP", 69: "TFTP", 161: "SNMP", 123: "NTP"
            }

            if packet.haslayer("TCP") or packet.haslayer("UDP"):
                sport = packet.sport
                dport = packet.dport
                for port in [sport, dport]:
                    if port in port_map:
                        return port_map[port]

            if packet.haslayer("Raw"):
                payload = packet["Raw"].load.decode(errors="ignore").lower()
                if "http" in payload or "host:" in payload:
                    return "HTTP"
                elif "ssh" in payload:
                    return "SSH"
                elif "ftp" in payload and "220" in payload:
                    return "FTP"
                elif "smtp" in payload or "mail from" in payload:
                    return "SMTP"
                elif "user" in payload and "pass" in payload:
                    return "POP3/IMAP"
                elif "get" in payload or "post" in payload:
                    return "HTTP"
                elif "dns" in payload:
                    return "DNS"

            return "Unknown"
        except:
            return "Error"

    def save_pcap(self, custom_path="captura_trafic.pcap"):
        wrpcap(custom_path, self.captured_packets)

    def classify_and_count(self, packet):
        proto = self.detect_application_protocol(packet)

        if proto == "HTTP":
            self.tcp_count += 1
        elif proto == "HTTPS":
            self.tcp_count += 1
        elif proto == "DNS":
            self.dns_count = getattr(self, "dns_count", 0) + 1
        elif proto == "ICMP":
            self.icmp_count = getattr(self, "icmp_count", 0) + 1
        elif proto == "ARP":
            self.arp_count = getattr(self, "arp_count", 0) + 1
        elif proto in ["FTP", "SSH", "TELNET", "SMTP", "POP3", "IMAP", "SMB", "MySQL", "RDP", "TFTP", "SNMP", "NTP"]:
            self.other_count += 1
        elif proto == "TCP":
            self.tcp_count += 1
        elif proto == "UDP":
            self.udp_count += 1
        else:
            self.other_count += 1

    def save_txt(self, filename="captura_trafic.txt"):
        with open(filename, "w") as file:
            for packet in self.captured_packets:
                file.write(str(packet) + "\n")

    def get_protocol_counts_and_reset(self):
        counts = dict(self.report_data.protocols)
        self.report_data.protocols.clear()
        return counts

    def finalize_report_data(self):
        # ✅ Transformă set() în listă pentru compatibilitate cu DiscoveryView
        self.report_data.connections = {
            src: list(dsts) for src, dsts in self.report_data.connections.items()
        }
