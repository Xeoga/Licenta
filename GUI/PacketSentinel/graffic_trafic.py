import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk

class TrafficGraph:
    def __init__(self, master):
        self.protocol_series = {}
        self.time_stamps = list(range(30))
        self.ip_traffic = {}
        self.selected_protocols = set()

        # Cadru pentru grafic
        self.border_frame = tk.Frame(master, bg="#3A3D4A", bd=2, relief="ridge")
        self.border_frame.place(x=452, y=110, width=500, height=280)

        # Grafic matplotlib
        self.figure, self.ax = plt.subplots(figsize=(6.5, 2.5), dpi=100)
        self.ax.set_facecolor("#1E1E1E")
        self.figure.patch.set_facecolor("#1E1E1E")
        self.ax.set_title("Grafic Protocoale Layer 7 / minut", color="white", pad=10)
        self.ax.set_xlabel("Minute", color="white", labelpad=10)
        self.ax.set_ylabel("Pachete", color="white", labelpad=10)
        self.ax.tick_params(colors="white")
        self.figure.subplots_adjust(left=0.15, right=0.95, top=0.85, bottom=0.2)

        self.canvas = FigureCanvasTkAgg(self.figure, master=self.border_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Iconiță setări (⚙) în colțul graficului
        self.protocol_config_icon = tk.Button(master, text="⚙", command=self.open_protocol_selector,
                                              font=("yu gothic ui", 12, "bold"), bg="#3A3D4A", fg="white",
                                              relief="flat", borderwidth=0, cursor="hand2")
        self.protocol_config_icon.place(x=920, y=110, width=25, height=25)

        # Tooltip
        self.protocol_config_icon.bind("<Enter>", self.show_tooltip)
        self.protocol_config_icon.bind("<Leave>", self.hide_tooltip)
        self.tooltip = None

        # Buton pentru statistici IP
        self.stats_button = tk.Button(master, text="Vezi Statistici IP", command=self.open_ip_stats_window,
                                      font=("yu gothic ui", 10), bg="#1D90F5", fg="white")
        self.stats_button.place(x=452, y=400, width=200, height=30)

    def show_tooltip(self, event):
        if not self.tooltip:
            self.tooltip = tk.Toplevel()
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.configure(bg="black")
            label = tk.Label(self.tooltip, text="Selectează protocoalele afișate",
                             bg="black", fg="white", padx=5, pady=2, font=("yu gothic ui", 9))
            label.pack()
        x = event.x_root + 10
        y = event.y_root + 10
        self.tooltip.wm_geometry(f"+{x}+{y}")

    def hide_tooltip(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def update_data(self, protocol_counts: dict):
        for proto, count in protocol_counts.items():
            if proto not in self.protocol_series:
                self.protocol_series[proto] = []
            self.protocol_series[proto].append(count)
            self.protocol_series[proto] = self.protocol_series[proto][-30:]
        self.time_stamps = list(range(1, max((len(lst) for lst in self.protocol_series.values()), default=1) + 1))
        self.draw()

    def draw(self):
        self.ax.clear()
        self.ax.set_facecolor("#1E1E1E")
        self.figure.patch.set_facecolor("#1E1E1E")

        colors = ["lime", "cyan", "orange", "yellow", "magenta", "white", "red", "blue", "violet", "gray"]
        for i, (proto, counts) in enumerate(self.protocol_series.items()):
            if self.selected_protocols and proto not in self.selected_protocols:
                continue
            color = colors[i % len(colors)]
            self.ax.plot(self.time_stamps[:len(counts)], counts, label=proto, color=color)

        self.ax.set_title("Grafic Protocoale Layer 7 / minut", color="white", pad=10)
        self.ax.set_xlabel("Minute", color="white", labelpad=10)
        self.ax.set_ylabel("Pachete", color="white", labelpad=10)
        self.ax.set_xlim(left=1, right=15)
        self.ax.set_xticks(list(range(1, 10)))
        self.ax.set_ylim(bottom=0)
        self.ax.tick_params(colors="white")

        self.ax.legend(loc="upper right", facecolor="#1E1E1E", edgecolor="white",
                       labelcolor="white", title="Protocoale")

        self.canvas.draw()

    def open_protocol_selector(self):
        selector_window = tk.Toplevel()
        selector_window.title("Selectează Protocoale")
        selector_window.configure(bg="#3A3D4A")
        selector_window.geometry("300x400")

        check_vars = {}

        def apply_selection():
            self.selected_protocols = {proto for proto, var in check_vars.items() if var.get()}
            selector_window.destroy()
            self.draw()

        for proto in self.protocol_series.keys():
            var = tk.BooleanVar(value=(proto in self.selected_protocols or not self.selected_protocols))
            check_vars[proto] = var
            cb = tk.Checkbutton(selector_window, text=proto, variable=var,
                                bg="#3A3D4A", fg="white", activebackground="#3A3D4A",
                                activeforeground="white", selectcolor="#3A3D4A")
            cb.pack(anchor="w", padx=20, pady=2)

        tk.Button(selector_window, text="Aplică", command=apply_selection,
                  font=("yu gothic ui", 10), bg="#1D90F5", fg="white").pack(pady=10)

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
        return 5000  # ms
