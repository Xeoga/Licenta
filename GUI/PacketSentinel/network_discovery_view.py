import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx
import geoip2.database
import os

class DiscoveryView:
    def __init__(self, master, report_data):
        self.sources = {}
        self.destinations = {}
        self.protocol_details = {}
        self.connections = {}

        self.window = tk.Toplevel(master)
        self.window.title("Host Discovery")
        self.window.geometry("1000x600")
        self.window.configure(bg="#1e1e1e")

        title = tk.Label(self.window, text="Hosturi Detectate în Rețea", font=("yu gothic ui bold", 16),
                         bg="#1e1e1e", fg="white")
        title.pack(pady=10)

        self.tabs = ttk.Notebook(self.window)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        self.table_tab = tk.Frame(self.tabs, bg="#1e1e1e")
        self.graph_tab = tk.Frame(self.tabs, bg="#1e1e1e")
        self.map_tab = tk.Frame(self.tabs, bg="#1e1e1e")

        self.tabs.add(self.table_tab, text="Tabel Hosturi")
        self.tabs.add(self.graph_tab, text="Grafic Interactiv")
        self.tabs.add(self.map_tab, text="Hartă Rețea")

        self.geo_data = self.load_geoip_data(report_data)

        self.init_table_view(report_data)
        self.init_graph_view(report_data)
        self.init_network_map_view(report_data)

    def load_geoip_data(self, report_data):
        geo_data = {}
        try:
            print(f"[DEBUG] CWD: {os.getcwd()}")
            reader = geoip2.database.Reader("PacketSentinel/GeoLite2-City.mmdb")
            all_ips = set(report_data.sources.keys()) | set(report_data.destinations.keys())
            for ip in all_ips:
                try:
                    response = reader.city(ip)
                    country = response.country.name or "N/A"
                    city = response.city.name or "N/A"
                    lat = response.location.latitude or "N/A"
                    lon = response.location.longitude or "N/A"
                    tz = response.location.time_zone or "N/A"
                    region = response.subdivisions.most_specific.name or "N/A"
                    org = response.traits.organization if hasattr(response.traits, 'organization') else "N/A"
                    geo_data[ip] = {
                        "country": country,
                        "city": city,
                        "region": region,
                        "latitude": lat,
                        "longitude": lon,
                        "timezone": tz,
                        "org": org
                    }
                except:
                    geo_data[ip] = {
                        "country": "N/A", "city": "N/A", "region": "N/A", "latitude": "N/A",
                        "longitude": "N/A", "timezone": "N/A", "org": "N/A"
                    }
            reader.close()
        except FileNotFoundError:
            print("Baza de date GeoLite2-City.mmdb nu a fost găsită.")
        return geo_data

    def init_table_view(self, report_data):
        columns = ("IP", "Rol", "Nr. Pachete", "Protocoale", "GeoLocație")
        tree = ttk.Treeview(self.table_tab, columns=columns, show="headings")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor="center")

        ip_protocols = {}
        for proto, ips in report_data.protocol_details.items():
            for ip, count in ips.items():
                ip_protocols.setdefault(ip, set()).add(proto)

        all_ips = set(report_data.sources.keys()) | set(report_data.destinations.keys())
        for ip in all_ips:
            role = "Sursă" if ip in report_data.sources else "Destinație"
            count = report_data.sources.get(ip, 0) + report_data.destinations.get(ip, 0)
            protocols = ", ".join(sorted(ip_protocols.get(ip, [])))
            location_data = self.geo_data.get(ip, {})
            location = f"{location_data.get('country', 'N/A')}, {location_data.get('city', 'N/A')}"
            tree.insert("", "end", values=(ip, role, count, protocols, location))

    def init_graph_view(self, report_data):
        fig, ax = plt.subplots(figsize=(9, 5), dpi=100)
        all_ips = {}
        for ip, count in report_data.sources.items():
            all_ips[ip] = all_ips.get(ip, 0) + count
        for ip, count in report_data.destinations.items():
            all_ips[ip] = all_ips.get(ip, 0) + count

        ips = list(all_ips.keys())
        counts = list(all_ips.values())

        ax.barh(ips[:15], counts[:15], color='skyblue')
        ax.set_title("Top 15 IP-uri activitate totală")
        ax.set_xlabel("Nr. pachete")
        ax.set_ylabel("IP-uri")
        ax.invert_yaxis()
        ax.grid(axis='x', linestyle='--', alpha=0.5)
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.graph_tab)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def init_network_map_view(self, report_data):
        fig, ax = plt.subplots(figsize=(10, 6), dpi=100, facecolor='#1e1e1e')
        fig.patch.set_facecolor('#1e1e1e')
        G = nx.DiGraph()

        if not hasattr(report_data, "connections") or report_data.connections is None:
            print("[WARN] report_data.connections nu există. Se creează unul gol.")
            report_data.connections = {}
        else:
            print(f"[DEBUG] Conexiuni detectate: {len(report_data.connections)} surse")

        total_edges = 0
        for src_ip, dst_list in report_data.connections.items():
            print(f"[DEBUG] {src_ip} -> {dst_list}")
            for dst_ip in dst_list:
                if src_ip != dst_ip:
                    G.add_edge(src_ip, dst_ip)
                    total_edges += 1
                else:
                    print(f"[INFO] Conexiune ignorată (loop): {src_ip} -> {dst_ip}")

        print(f"[DEBUG] Noduri în grafic: {len(G.nodes())}")
        print(f"[DEBUG] Legături (edge-uri) în grafic: {total_edges}")

        if len(G.nodes) == 0:
            ax.text(0.5, 0.5, "Nicio conexiune detectată", color="white", fontsize=14,
                    ha="center", va="center", transform=ax.transAxes)
        else:
            pos = nx.spring_layout(G, seed=42)
            nx.draw_networkx_nodes(G, pos, node_size=800, node_color="#3BAFDA", ax=ax)
            nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=10, edge_color="gray", ax=ax)

            labels = {}
            for node in G.nodes():
                loc = self.geo_data.get(node, {})
                label_lines = [node]
                if loc:
                    label_lines.append(f"{loc.get('country', '')}, {loc.get('city', '')}")
                    if loc.get('org', '') != "N/A":
                        label_lines.append(f"{loc.get('org')}")
                labels[node] = "\n".join(filter(None, label_lines))

            nx.draw_networkx_labels(G, pos, labels=labels, font_size=7, font_color="white", ax=ax)

        ax.set_title("Vizualizare Topologică Rețea", fontsize=12, color="white")
        ax.set_facecolor("#1e1e1e")
        ax.tick_params(left=False, bottom=False, labelleft=False, labelbottom=False)
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.map_tab)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
