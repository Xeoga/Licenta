import tkinter as tk
import threading
import time
import subprocess
from tkinter import messagebox, filedialog

from core import TrafficAnalyzerCore
from interface_utils import coreleaza_interfete
from graffic_trafic import TrafficGraph
from packet_display import PacketDisplay
from alert_box import AlertBox
from detector import Detector

class TrafficAnalyzerGUI:
    def __init__(self, root, username="Guest"):
        self.root = root
        self.username = username
        self.root.title("Sentinel Traffic Analyzer")
        self.root.configure(bg="#525561")
        self.root.overrideredirect(True)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"{screen_width}x{screen_height}+0+0")
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)
        self.root.bind("<Map>", self.restore_window)
        self.total_packets = 0

        self.detector = Detector()

        self.title_bar = tk.Frame(self.root, bg="#1A1A1A", relief="raised", bd=0, height=30)
        self.title_bar.pack(fill=tk.X)
        self.offset_x = 0
        self.offset_y = 0
        self.title_bar.bind("<Button-1>", self.click_title_bar)
        self.title_bar.bind("<B1-Motion>", self.drag_title_bar)

        self.title_label = tk.Label(self.title_bar, text="Sentinel Traffic Analyzer", bg="#1A1A1A", fg="white",
                                    font=("yu gothic ui bold", 10))
        self.title_label.pack(side=tk.LEFT, padx=10)
        self.minimize_button = tk.Button(self.title_bar, text="━", command=self.minimize_app,
                                         bg="#1A1A1A", fg="white", bd=0, font=("Arial", 12), width=4, cursor="hand2")
        self.minimize_button.pack(side=tk.RIGHT, padx=2)
        self.close_button = tk.Button(self.title_bar, text="✕", command=self.close_app,
                                      bg="#1A1A1A", fg="white", bd=0, font=("Arial", 12), width=4, cursor="hand2")
        self.close_button.pack(side=tk.RIGHT)

        self.bg_frame = tk.Frame(self.root, bg="#272A37", bd=0)
        self.bg_frame.pack(fill=tk.BOTH, expand=True)

        self.alert_box = AlertBox(self.bg_frame)
        tk.Label(self.bg_frame, text="Sentinel", font=("yu gothic ui bold", 20), bg="#272A37", fg="white").place(x=30, y=30)

        self.top_button_frame = tk.Frame(self.bg_frame, bg="#272A37")
        self.top_button_frame.place(x=30, y=75)

        self.packet_button = tk.Button(self.top_button_frame, text="PacketSentinel", font=("yu gothic ui", 12, "bold"),
                                       bg="#4A4A4A", fg="white", relief=tk.FLAT, cursor="hand2", width=15)
        self.packet_button.pack(side=tk.LEFT, padx=5)

        self.hash_button = tk.Button(self.top_button_frame, text="HashSentinel", font=("yu gothic ui", 12, "bold"),
                                     bg="#4A4A4A", fg="white", relief=tk.FLAT, cursor="hand2", width=15)
        self.hash_button.pack(side=tk.LEFT, padx=5)

        tk.Label(self.bg_frame, text="Traffic Analyzer", font=("yu gothic ui bold", 26), bg="#272A37", fg="white").place(x=30, y=150)
        tk.Label(self.bg_frame, text="Selectează interfața:", font=("yu gothic ui bold", 14), bg="#272A37", fg="white").place(x=30, y=190)

        self.interface_map = {}
        self.interfaces = []
        corelate = coreleaza_interfete()
        for entry in corelate:
            display_name = f"{entry['description']} ({entry['ip']})"
            self.interfaces.append(display_name)
            self.interface_map[display_name] = entry["scapy_name"]

        self.selected_interface = tk.StringVar()
        default_interface = self.interfaces[0] if self.interfaces else "Nicio interfață"
        self.selected_interface.set(default_interface)
        self.interface_menu = tk.OptionMenu(self.bg_frame, self.selected_interface, *self.interfaces)
        self.interface_menu.config(bg="#3D404B", fg="white", font=("yu gothic ui", 12), width=30)
        self.interface_menu["menu"].config(bg="#3D404B", fg="white")
        self.interface_menu.place(x=30, y=220)

        tk.Label(self.bg_frame, text="Filtru (ex: tcp, udp, port 80):", font=("yu gothic ui bold", 14), bg="#272A37", fg="white").place(x=30, y=260)
        self.filter_entry = tk.Entry(self.bg_frame, font=("yu gothic ui", 12), bg="#3D404B", fg="white", width=30)
        self.filter_entry.place(x=30, y=300)

        self.graph = TrafficGraph(self.bg_frame)

        self.start_button = tk.Button(self.bg_frame, text="Start Captură", command=self.start_sniffing,
                                      font=("yu gothic ui bold", 12), bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.start_button.place(x=30, y=340, width=180, height=40)

        self.stop_button = tk.Button(self.bg_frame, text="Stop Captură", command=self.stop_sniffing,
                                     font=("yu gothic ui bold", 12), state=tk.DISABLED,
                                     bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.stop_button.place(x=220, y=340, width=180, height=40)

        self.packet_display = PacketDisplay(self.bg_frame)

        self.packet_rate_label = tk.Label(self.bg_frame, text="📈 Pachete/secundă: 0", font=("yu gothic ui", 12), bg="#272A37", fg="white")
        self.packet_rate_label.place(x=30, y=740)
        self.total_label = tk.Label(self.bg_frame, text="📦 Total pachete: 0", font=("yu gothic ui", 12), bg="#272A37", fg="white")
        self.total_label.place(x=280, y=740)

        self.save_button = tk.Button(self.bg_frame, text="Salvează PCAP", command=self.save_pcap,
                                     font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_button.place(x=30, y=780, width=180, height=40)

        self.save_txt_button = tk.Button(self.bg_frame, text="Salvează TXT", command=self.save_txt,
                                         font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_txt_button.place(x=220, y=780, width=180, height=40)

        self.user_frame = tk.Frame(self.bg_frame, bg="#272A37")
        self.user_frame.place(relx=1.0, y=30, anchor="ne")

        self.welcome_label = tk.Label(self.user_frame, text=f"Welcome {self.username}", font=("yu gothic ui bold", 12), bg="#272A37", fg="white")
        self.welcome_label.pack(side=tk.LEFT, padx=10)

        self.logout_button = tk.Button(
            self.user_frame, text="Delogare", font=("yu gothic ui", 10),
            command=self.logout_user, bg="#3D404B", fg="white", relief="flat", cursor="hand2"
        )
        self.logout_button.pack(side=tk.LEFT, padx=10)

        tk.Label(self.bg_frame, text="Author: ~d0gma Team", font=("yu gothic ui", 12), bg="#272A37", fg="#AAAAAA").place(relx=0.75, rely=0.95)

        self.analyzer = TrafficAnalyzerCore()
        self.sniffing_thread = None
        self.running = False

    def update_packet_rate(self):
        if self.running:
            counts = self.analyzer.get_protocol_counts_and_reset()
            tcp, udp, other = counts.get("TCP", 0), counts.get("UDP", 0), counts.get("Other", 0)
            self.packet_rate_label.config(text=f"📈 Pachete/minut: {tcp + udp + other}")
            self.graph.update_data(tcp, udp, other)
            self.root.after(self.graph.get_update_interval(), self.update_packet_rate)

    def start_sniffing(self):
        iface_display = self.selected_interface.get()
        iface_real = self.interface_map.get(iface_display, iface_display)
        bpf_filter = self.filter_entry.get().strip() or None
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.root.after(1000, self.update_packet_rate)
        self.running = True
        self.sniffing_thread = threading.Thread(
            target=lambda: self.analyzer.start_capture(iface_real, self.display_packet_counted, bpf_filter),
            daemon=True
        )
        self.sniffing_thread.start()
        self.packet_display.write(f"🟢 Captură începută cu filtru: {bpf_filter or 'fără filtru'}\n")
        self.packet_display.set_border_color("#00C853")

    def stop_sniffing(self):
        self.analyzer.stop_capture()
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.packet_display.write("🔴 Captură oprită.\n")
        self.packet_display.set_border_color("#D32F2F")

    def save_pcap(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Salvează fișierul PCAP"
        )
        if file_path:
            self.analyzer.save_pcap(custom_path=file_path)
            self.packet_display.write(f"📂 PCAP salvat la: {file_path}\n")
        else:
            self.packet_display.write("⚠️ Salvarea a fost anulată de utilizator.\n")

    def save_txt(self):
        self.analyzer.save_txt()
        self.packet_display.write("📂 DB salvarea în baza de date.\n")

    def display_packet(self, line):
        self.packet_display.write(line)

    def display_packet_counted(self, line):
        self.analyzer.classify_and_count(line)
        self.display_packet(line)
        self.total_packets += 1
        self.total_label.config(text=f"📦 Total pachete: {self.total_packets}")

        alerts = self.detector.process_packet(line)
        for msg, level in alerts:
            self.alert_box.add_alert(msg, level=level)

    def close_app(self):
        if messagebox.askokcancel("Ieșire", "Ești sigur că vrei să închizi aplicația?"):
            self.root.destroy()

    def minimize_app(self):
        self.root.overrideredirect(False)
        self.root.iconify()

    def restore_window(self, event=None):
        self.root.overrideredirect(True)

    def click_title_bar(self, event):
        self.offset_x = event.x
        self.offset_y = event.y

    def drag_title_bar(self, event):
        x = self.root.winfo_pointerx() - self.offset_x
        y = self.root.winfo_pointery() - self.offset_y
        self.root.geometry(f"+{x}+{y}")

    def logout_user(self):
        if messagebox.askyesno("Delogare", "Ești sigur că vrei să te deloghezi?"):
            self.root.destroy()
            subprocess.Popen(["python.exe", "GUI/login_page.py"])
