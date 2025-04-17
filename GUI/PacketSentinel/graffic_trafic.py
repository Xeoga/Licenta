import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk

class TrafficGraph:
    def __init__(self, master):
        self.packet_counts_tcp = []
        self.packet_counts_udp = []
        self.packet_counts_other = []
        self.time_stamps = list(range(30))
        self.ip_traffic = {}  # Dicționar pentru statistici IP

        # Cadru bordură pentru grafic
        self.border_frame = tk.Frame(master, bg="#3A3D4A", bd=2, relief="ridge")
        self.border_frame.place(x=452, y=110, width=500, height=280)

        # Graficul
        self.figure, self.ax = plt.subplots(figsize=(6.5, 2.5), dpi=100)
        self.ax.set_facecolor("#1E1E1E")
        self.figure.patch.set_facecolor("#1E1E1E")
        self.ax.set_title("Grafic Pachete/minut", color="white", pad=10)
        self.ax.set_xlabel("Minute", color="white", labelpad=10)
        self.ax.set_ylabel("Pachete", color="white", labelpad=10)
        self.ax.tick_params(colors="white")
        self.figure.subplots_adjust(left=0.15, right=0.95, top=0.85, bottom=0.2)

        self.canvas = FigureCanvasTkAgg(self.figure, master=self.border_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Buton pentru statistici IP
        self.stats_button = tk.Button(master, text="Vezi Statistici IP", command=self.open_ip_stats_window,
                                      font=("yu gothic ui", 10), bg="#1D90F5", fg="white")
        self.stats_button.place(x=452, y=400, width=200, height=30)

        self.update_data(0, 0, 0)  # Inițializare

    def update_data(self, tcp, udp, other):
        self.packet_counts_tcp.append(tcp)
        self.packet_counts_udp.append(udp)
        self.packet_counts_other.append(other)

        self.packet_counts_tcp = self.packet_counts_tcp[-30:]
        self.packet_counts_udp = self.packet_counts_udp[-30:]
        self.packet_counts_other = self.packet_counts_other[-30:]
        self.time_stamps = list(range(1, len(self.packet_counts_tcp) + 1))

        self.draw()

    def draw(self):
        self.ax.clear()
        self.ax.set_facecolor("#1E1E1E")
        self.figure.patch.set_facecolor("#1E1E1E")

        self.ax.plot(self.time_stamps, self.packet_counts_tcp, color="lime", label="TCP")
        self.ax.plot(self.time_stamps, self.packet_counts_udp, color="cyan", label="UDP")
        self.ax.plot(self.time_stamps, self.packet_counts_other, color="orange", label="Other")

        self.ax.set_title("Grafic Pachete/minut", color="white", pad=10)
        self.ax.set_xlabel("Minute", color="white", labelpad=10)
        self.ax.set_ylabel("Pachete", color="white", labelpad=10)

        self.ax.set_xlim(left=1, right=30)
        self.ax.set_ylim(bottom=0)

        self.ax.tick_params(colors="white")
        self.ax.legend(loc="upper right", facecolor="#1E1E1E", edgecolor="white", labelcolor="white")
        self.canvas.draw()

    def update_ip_traffic(self, ip, tcp=0, udp=0, other=0):
        if ip not in self.ip_traffic:
            self.ip_traffic[ip] = {"tcp": 0, "udp": 0, "other": 0}
        self.ip_traffic[ip]["tcp"] += tcp
        self.ip_traffic[ip]["udp"] += udp
        self.ip_traffic[ip]["other"] += other

    def open_ip_stats_window(self):
        stats_window = tk.Toplevel()
        stats_window.title("Statistici pe IP")
        stats_window.configure(bg="#3A3D4A")
        stats_window.geometry("500x400")

        table = ttk.Treeview(stats_window, columns=("IP", "TCP", "UDP", "Other"), show="headings")
        table.heading("IP", text="Adresa IP")
        table.heading("TCP", text="TCP")
        table.heading("UDP", text="UDP")
        table.heading("Other", text="Other")
        table.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for ip, data in self.ip_traffic.items():
            table.insert("", "end", values=(ip, data["tcp"], data["udp"], data["other"]))

        close_btn = tk.Button(stats_window, text="Închide", command=stats_window.destroy,
                              font=("yu gothic ui", 10), bg="#F55353", fg="white")
        close_btn.pack(pady=10)

    def get_update_interval(self):
        return 5000  # 5 secunde în milisecunde