import os
import json
from datetime import datetime
from collections import defaultdict
from fpdf import FPDF
import matplotlib.pyplot as plt
import networkx as nx

class ReportData:
    def __init__(self):
        self.total_packets = 0
        self.start_time = None
        self.end_time = None
        self.sources = defaultdict(int)
        self.destinations = defaultdict(int)
        self.protocols = defaultdict(int)
        self.protocol_details = defaultdict(lambda: defaultdict(int))  # protocol -> ip -> count
        self.alerts = defaultdict(int)
        self.packets_per_minute = defaultdict(int)
        self.connections = defaultdict(set)

    def add_connection(self, src_ip, dst_ip):
        if src_ip and dst_ip and src_ip != dst_ip:
            self.connections[src_ip].add(dst_ip)

    def to_dict(self):
        return {
            "total_packets": self.total_packets,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "sources": dict(self.sources),
            "destinations": dict(self.destinations),
            "protocols": dict(self.protocols),
            "protocol_details": {proto: dict(ips) for proto, ips in self.protocol_details.items()},
            "alerts": dict(self.alerts),
            "packets_per_minute": dict(self.packets_per_minute),
            "connections": {src: list(dsts) for src, dsts in self.connections.items()}
        }

    def export_json(self, path="raport_statistic.json"):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=4)

    def generate_network_map(self):
        if not self.connections:
            return
        G = nx.Graph()
        for src, dsts in self.connections.items():
            for dst in dsts:
                G.add_edge(src, dst)

        plt.figure(figsize=(8, 6))
        pos = nx.spring_layout(G, k=0.5)
        nx.draw(G, pos, with_labels=True, node_color='lightblue', edge_color='gray', node_size=1500, font_size=8)
        plt.title("Harta rețelei (conexiuni IP)")
        plt.tight_layout()
        plt.savefig("network_map.png")
        plt.close()

    def generate_graphs(self):
        if self.protocols:
            plt.figure(figsize=(6, 4))
            plt.bar(self.protocols.keys(), self.protocols.values(), color='skyblue')
            plt.title("Protocoale detectate")
            plt.tight_layout()
            plt.savefig("protocol_chart.png")
            plt.close()

        if self.alerts:
            plt.figure(figsize=(5, 5))
            plt.pie(self.alerts.values(), labels=self.alerts.keys(), autopct='%1.1f%%', startangle=90)
            plt.title("Distribuție alerte")
            plt.tight_layout()
            plt.savefig("alert_pie.png")
            plt.close()

        if self.packets_per_minute:
            x = sorted(self.packets_per_minute.keys())
            y = [self.packets_per_minute[k] for k in x]
            plt.figure(figsize=(6, 4))
            plt.plot(x, y, marker='o', linestyle='-', color='green')
            plt.xticks(rotation=45)
            plt.title("Pachete pe minut")
            plt.tight_layout()
            plt.savefig("packets_time_chart.png")
            plt.close()

        for proto, ips in self.protocol_details.items():
            if not ips:
                continue
            plt.figure(figsize=(6, 4))
            plt.bar(ips.keys(), ips.values(), color='orange')
            plt.title(f"{proto} - trafic pe IP")
            plt.xticks(rotation=45)
            plt.tight_layout()
            filename = f"protocol_{proto}_chart.png".replace("/", "_").replace(" ", "_")
            plt.savefig(filename)
            plt.close()

        self.generate_network_map()

    def export_pdf_report(self, path="raport_final.pdf"):
        def clean(text):
            return text.replace("ă", "a").replace("â", "a").replace("î", "i").replace("ș", "s").replace("ț", "t")

        self.generate_graphs()

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, clean("Raport Captura Trafic"), ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", '', 12)
        pdf.cell(0, 10, clean(f"Total pachete: {self.total_packets}"), ln=True)
        pdf.cell(0, 10, clean(f"Start captura: {self.start_time}"), ln=True)
        pdf.cell(0, 10, clean(f"Sfarsit captura: {self.end_time}"), ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, clean("Protocoale detectate:"), ln=True)
        pdf.set_font("Arial", '', 12)
        for proto, count in self.protocols.items():
            pdf.cell(0, 8, clean(f" - {proto}: {count}"), ln=True)
            for ip, ip_count in sorted(self.protocol_details[proto].items(), key=lambda x: x[1], reverse=True)[:3]:
                pdf.cell(0, 8, clean(f"    -> {ip}: {ip_count}"), ln=True)

        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, clean("Top IP-uri sursa:"), ln=True)
        pdf.set_font("Arial", '', 12)
        for ip, count in sorted(self.sources.items(), key=lambda x: x[1], reverse=True)[:5]:
            pdf.cell(0, 8, clean(f" - {ip}: {count}"), ln=True)

        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, clean("Top IP-uri destinatie:"), ln=True)
        pdf.set_font("Arial", '', 12)
        for ip, count in sorted(self.destinations.items(), key=lambda x: x[1], reverse=True)[:5]:
            pdf.cell(0, 8, clean(f" - {ip}: {count}"), ln=True)

        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, clean("Alerte generate:"), ln=True)
        pdf.set_font("Arial", '', 12)
        for alert, count in self.alerts.items():
            pdf.cell(0, 8, clean(f" - {alert}: {count}"), ln=True)

        all_imgs = [
            "protocol_chart.png", "alert_pie.png", "packets_time_chart.png", "network_map.png"
        ]
        # Excludem protocol_chart.png din lista dinamica
        all_imgs += [
            f for f in os.listdir('.') 
            if f.startswith("protocol_") and f.endswith("_chart.png") and f != "protocol_chart.png"
        ]

        for img in all_imgs:
            if os.path.exists(img):
                pdf.add_page()
                pdf.image(img, x=15, y=30, w=180)

        pdf.output(path)

