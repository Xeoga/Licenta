### gui.py ###
import tkinter as tk
import threading
import wmi
import re
from scapy.all import get_if_list
from core import TrafficAnalyzerCore
from tkinter import messagebox

class TrafficAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel Traffic Analyzer")
        self.root.configure(bg="#525561")
        self.root.overrideredirect(True)

        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"{screen_width}x{screen_height}+0+0")

        self.root.protocol("WM_DELETE_WINDOW", self.close_app)
        self.root.bind("<Map>", self.restore_window)

        # ================= CUSTOM TITLE BAR ==================
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

        # ================= MAIN BG FRAME ==================
        self.bg_frame = tk.Frame(self.root, bg="#272A37", bd=0)
        self.bg_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(self.bg_frame, text="Sentinel", font=("yu gothic ui bold", 20), bg="#272A37", fg="white").place(x=30, y=30)

        self.top_button_frame = tk.Frame(self.bg_frame, bg="#272A37")
        self.top_button_frame.place(x=30, y=75)

        self.packet_button = tk.Button(self.top_button_frame, text="PacketSentinel", font=("yu gothic ui", 12, "bold"),
                                       bg="#4A4A4A", fg="#FFFFFF", activebackground="#5A5A5A", activeforeground="#FFFFFF",
                                       relief=tk.FLAT, cursor="hand2", width=15)
        self.packet_button.pack(side=tk.LEFT, padx=5)

        self.hash_button = tk.Button(self.top_button_frame, text="HashSentinel", font=("yu gothic ui", 12, "bold"),
                                     bg="#4A4A4A", fg="#FFFFFF", activebackground="#5A5A5A", activeforeground="#FFFFFF",
                                     relief=tk.FLAT, cursor="hand2", width=15)
        self.hash_button.pack(side=tk.LEFT, padx=5)

        self.dir_search = tk.Button(self.top_button_frame, text="DirSentinel", font=("yu gothic ui", 12, "bold"),
                                    bg="#4A4A4A", fg="#FFFFFF", activebackground="#5A5A5A", activeforeground="#FFFFFF",
                                    relief=tk.FLAT, cursor="hand2", width=15)
        self.dir_search.pack(side=tk.LEFT, padx=5)

        tk.Label(self.bg_frame, text="Traffic Analyzer", font=("yu gothic ui bold", 26), bg="#272A37", fg="white").place(x=30, y=150)
        tk.Label(self.bg_frame, text="Selectează interfața:", font=("yu gothic ui bold", 14), bg="#272A37", fg="white").place(x=30, y=220)

        raw_interfaces = get_if_list()
        c = wmi.WMI()
        guid_to_name = {nic.SettingID.upper(): nic.Description for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True) if nic.SettingID and nic.Description}

        self.interface_map = {}
        self.interfaces = []

        for iface in raw_interfaces:
            match = re.search(r'{(.+?)}', iface)
            if match:
                guid = match.group(1).upper()
                name = guid_to_name.get(guid, "Interfață necunoscută")
                display_name = f"{name} ({guid[:6]}...)"
            elif "Loopback" in iface:
                display_name = "Loopback"
            else:
                display_name = iface
            self.interfaces.append(display_name)
            self.interface_map[display_name] = iface

        self.selected_interface = tk.StringVar(value=self.interfaces[0] if self.interfaces else "None")
        self.interface_menu = tk.OptionMenu(self.bg_frame, self.selected_interface, *self.interfaces)
        self.interface_menu.config(bg="#3D404B", fg="white", font=("yu gothic ui", 12), width=30)
        self.interface_menu["menu"].config(bg="#3D404B", fg="white")
        self.interface_menu.place(x=30, y=220)

        self.start_button = tk.Button(self.bg_frame, text="Start Captură", command=self.start_sniffing,
                                      font=("yu gothic ui bold", 12), bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.start_button.place(x=30, y=280, width=180, height=40)

        self.stop_button = tk.Button(self.bg_frame, text="Stop Captură", command=self.stop_sniffing,
                                     font=("yu gothic ui bold", 12), state=tk.DISABLED,
                                     bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.stop_button.place(x=220, y=280, width=180, height=40)

        self.save_button = tk.Button(self.bg_frame, text="Salvează PCAP", command=self.save_pcap,
                                     font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_button.place(x=30, y=330, width=180, height=40)

        self.save_txt_button = tk.Button(self.bg_frame, text="Salvează TXT", command=self.save_txt,
                                         font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_txt_button.place(x=220, y=330, width=180, height=40)

        self.output_text = tk.Text(self.bg_frame, bg="#1E1E1E", fg="white", font=("Consolas", 10), insertbackground="white", wrap="word", bd=0)
        self.output_text.place(x=30, y=390, relwidth=0.9, height=320)

        tk.Label(self.bg_frame, text="Author: ~d0gma Team", font=("yu gothic ui", 12), bg="#272A37", fg="#AAAAAA").place(relx=0.75, rely=0.95)

        self.analyzer = TrafficAnalyzerCore()
        self.sniffing_thread = None

    def start_sniffing(self):
        iface_display = self.selected_interface.get()
        iface_real = self.interface_map.get(iface_display, iface_display)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffing_thread = threading.Thread(target=lambda: self.analyzer.start_capture(iface_real, self.display_packet), daemon=True)
        self.sniffing_thread.start()
        self.output_text.insert(tk.END, "🟢 Captură începută...\n")
        self.output_text.see(tk.END)

    def stop_sniffing(self):
        self.analyzer.stop_capture()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.output_text.insert(tk.END, "🔴 Captură oprită.\n")
        self.output_text.see(tk.END)

    def save_pcap(self):
        self.analyzer.save_pcap()
        self.output_text.insert(tk.END, "💾 PCAP salvat ca captura_trafic.pcap\n")
        self.output_text.see(tk.END)

    def save_txt(self):
        self.analyzer.save_txt()
        self.output_text.insert(tk.END, "💾 TXT salvat ca captura_trafic.txt\n")
        self.output_text.see(tk.END)

    def display_packet(self, line):
        self.output_text.insert(tk.END, line)
        self.output_text.see(tk.END)

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