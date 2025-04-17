from scapy.all import sniff, wrpcap
import datetime
import re
class TrafficAnalyzerCore:
    def __init__(self):
        self.stop_sniff = False
        self.captured_packets = []
        self.tcp_count = 0
        self.udp_count = 0
        self.other_count = 0

    def start_capture(self, iface, callback, bpf_filter=None):
        self.stop_sniff = False
        sniff(
            iface=iface,
            prn=lambda pkt: self._handle_packet(pkt, callback),
            stop_filter=lambda x: self.stop_sniff,
            filter=bpf_filter if bpf_filter else None  # Captură totală dacă nu e filtru
        )

    def stop_capture(self):
        self.stop_sniff = True

    def _handle_packet(self, packet, callback):
        self.captured_packets.append(packet)
        callback(self.format_packet(packet))

    def format_packet(self, packet):
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            length = len(packet)
            index = len(self.captured_packets)

            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                protocol = "TCP" if packet.haslayer("TCP") else "UDP" if packet.haslayer("UDP") else f"IP-{packet['IP'].proto}"
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

    def save_pcap(self, filename="captura_trafic.pcap"):
        wrpcap(filename, self.captured_packets)
        
    def classify_and_count(self, packet_summary):
        if "TCP" in packet_summary:
            self.tcp_count += 1
        elif "UDP" in packet_summary:
            self.udp_count += 1
        elif "ICMP" in packet_summary:
            self.icmp_count = getattr(self, "icmp_count", 0) + 1
        elif "ARP" in packet_summary:
            self.arp_count = getattr(self, "arp_count", 0) + 1
        elif "DNS" in packet_summary:
            self.dns_count = getattr(self, "dns_count", 0) + 1
        else:
            self.other_count += 1

    def save_txt(self, filename="captura_trafic.txt"):
        with open(filename, "w") as file:
            for packet in self.captured_packets:
                file.write(str(packet) + "\n")

    def get_protocol_counts_and_reset(self):
        counts = {
            "TCP": self.tcp_count,
            "UDP": self.udp_count,
            "ICMP": getattr(self, "icmp_count", 0),
            "ARP": getattr(self, "arp_count", 0),
            "DNS": getattr(self, "dns_count", 0),
            "Other": self.other_count
        }

        self.tcp_count = self.udp_count = self.other_count = 0
        self.icmp_count = self.arp_count = self.dns_count = 0

        return counts