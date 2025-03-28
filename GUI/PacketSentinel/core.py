### core.py ###
from scapy.all import sniff, wrpcap, IP, TCP, UDP
import datetime

class TrafficAnalyzerCore:
    def __init__(self):
        self.stop_sniff = False
        self.captured_packets = []

    def start_capture(self, iface, callback):
        self.stop_sniff = False
        sniff(iface=iface, prn=lambda pkt: self._handle_packet(pkt, callback), stop_filter=lambda x: self.stop_sniff)

    def stop_capture(self):
        self.stop_sniff = True

    def _handle_packet(self, packet, callback):
        self.captured_packets.append(packet)
        callback(self.format_packet(packet))

    def format_packet(self, packet):
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "UNKNOWN"
            length = len(packet)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            info = ""

            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                info = f"{sport} → {dport} [TCP]"
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                info = f"{sport} → {dport} [UDP]"
            else:
                info = "Alt tip de pachet"

            index = len(self.captured_packets)
            return f"{index:<5} {timestamp:<15} {src_ip:<18} {dst_ip:<18} {protocol:<8} {length:<7} {info}\n"
        except Exception:
            return "[Eroare la parsarea pachetului]\n"

    def save_pcap(self, filename="captura_trafic.pcap"):
        wrpcap(filename, self.captured_packets)

    def save_txt(self, filename="captura_trafic.txt"):
        with open(filename, "w") as file:
            for packet in self.captured_packets:
                file.write(str(packet) + "\n")