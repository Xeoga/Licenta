import tkinter as tk
import threading
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from scapy.utils import wrpcap
import wmi
import re

class TrafficAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel Traffic Analyzer")
        self.root.configure(bg="#525561")

        width, height = 1300, 800
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 4) - (height // 4)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.overrideredirect(True)
        self.root.attributes("-transparentcolor", "#525561")

        self.bg_frame = tk.Frame(self.root, bg="#272A37", bd=0)
        self.bg_frame.place(x=120, y=28, width=1060, height=740)

        # ================= HEADER ==================
        tk.Label(self.bg_frame, text="Sentinel", font=("yu gothic ui bold", 20), bg="#272A37", fg="white").place(x=30, y=30)
        tk.Label(self.bg_frame, text="Traffic Analyzer", font=("yu gothic ui bold", 26), bg="#272A37", fg="white").place(x=30, y=75)

        # ================= TOP BUTTONS ==================
        self.top_button_frame = tk.Frame(self.bg_frame, bg="#272A37")
        self.top_button_frame.place(x=30, y=130)
        # ================= PacketSentinel ===============
        self.packet_button = tk.Button(
            self.top_button_frame,
            text="PacketSentinel",
            # command=self.open_wireshark, -> link pentru main_Packet.py
            font=("yu gothic ui", 12, "bold"),
            bg="#4A4A4A", fg="#FFFFFF",
            activebackground="#5A5A5A", activeforeground="#FFFFFF",
            relief=tk.FLAT, cursor="hand2", width=15
        )
        self.packet_button.pack(side=tk.LEFT, padx=5)
        # ================= HashSentinel ===============
        self.hash_button = tk.Button(
            self.top_button_frame,
            text="HashSentinel",
            # command=self.open_wireshark, -> Aici trebuie de lincuit cu aplicati lui Adrian
            font=("yu gothic ui", 12, "bold"),
            bg="#4A4A4A", fg="#FFFFFF",
            activebackground="#5A5A5A", activeforeground="#FFFFFF",
            relief=tk.FLAT, cursor="hand2", width=15
        )
        self.hash_button.pack(side=tk.LEFT, padx=5)
        # ================= HideDirectorySentinel ======
        # ...
        # ================= INTERFACE MENU (cu denumiri reale) ==================
        tk.Label(self.bg_frame, text="Selectează interfața:", font=("yu gothic ui bold", 14),
                 bg="#272A37", fg="white").place(x=30, y=190)

        raw_interfaces = get_if_list()
        c = wmi.WMI()
        guid_to_name = {}
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.SettingID and nic.Description:
                guid_to_name[nic.SettingID.upper()] = nic.Description

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

        # ================= CONTROL BUTTONS ==================
        self.start_button = tk.Button(self.bg_frame, text="Start Captură", command=self.start_sniffing,
                                      font=("yu gothic ui bold", 12),
                                      bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.start_button.place(x=30, y=280, width=180, height=40)

        self.stop_button = tk.Button(self.bg_frame, text="Stop Captură", command=self.stop_sniffing,
                                     font=("yu gothic ui bold", 12), state=tk.DISABLED,
                                     bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.stop_button.place(x=220, y=280, width=180, height=40)

        self.save_button = tk.Button(self.bg_frame, text="Salvează PCAP", command=self.save_pcap,
                                     font=("yu gothic ui bold", 12),
                                     bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_button.place(x=30, y=330, width=180, height=40)

        self.save_txt_button = tk.Button(self.bg_frame, text="Salvează TXT", command=self.save_txt,
                                         font=("yu gothic ui bold", 12),
                                         bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_txt_button.place(x=220, y=330, width=180, height=40)

        # ================= OUTPUT TEXT ==================
        self.output_text = tk.Text(self.bg_frame, bg="#1E1E1E", fg="white",
                                   font=("Consolas", 10), insertbackground="white", wrap="word", bd=0)
        self.output_text.place(x=30, y=390, width=1000, height=320)

        # ================= FOOTER ==================
        tk.Label(self.bg_frame, text="Author: ~d0gma Team", font=("yu gothic ui", 12),
                 bg="#272A37", fg="#AAAAAA").place(x=800, y=710)

        # ================= INIT VARS ==================
        self.sniffing_thread = None
        self.stop_sniff = False
        self.captured_packets = []

    def open_wireshark(self):
        self.output_text.insert(tk.END, "🔗 Deschidere Wireshark...\n")
        self.output_text.see(tk.END)
        try:
            import subprocess
            subprocess.Popen(["wireshark"])
        except Exception as e:
            self.output_text.insert(tk.END, f"Eroare: {str(e)}\n")

    def start_sniffing(self):
        self.stop_sniff = False
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffing_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffing_thread.start()
        self.output_text.insert(tk.END, "🟢 Captură începută...\n")
        self.output_text.see(tk.END)

    def stop_sniffing(self):
        self.stop_sniff = True
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.output_text.insert(tk.END, "🔴 Captură oprită.\n")
        self.output_text.see(tk.END)

    def sniff_packets(self):
        iface_display = self.selected_interface.get()
        iface_real = self.interface_map.get(iface_display, iface_display)
        sniff(iface=iface_real, prn=self.packet_callback, stop_filter=lambda x: self.stop_sniff)

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "UNKNOWN"
            info = (
                f"\n==============================\n"
                f"📡 Pachet Capturat:\n"
                f"🔹 Sursă: {src_ip}\n"
                f"🔹 Destinație: {dst_ip}\n"
                f"🔹 Protocol: {protocol}\n"
                f"==============================\n"
            )
            self.output_text.insert(tk.END, info)
            self.output_text.see(tk.END)
            self.captured_packets.append(packet)

    def save_pcap(self):
        if self.captured_packets:
            wrpcap("captura_trafic.pcap", self.captured_packets)
            self.output_text.insert(tk.END, "💾 PCAP salvat ca captura_trafic.pcap\n")
        else:
            self.output_text.insert(tk.END, "⚠️ Nu există pachete capturate.\n")
        self.output_text.see(tk.END)

    def save_txt(self):
        with open("captura_trafic.txt", "w") as file:
            for packet in self.captured_packets:
                file.write(str(packet) + "\n")
        self.output_text.insert(tk.END, "💾 TXT salvat ca captura_trafic.txt\n")
        self.output_text.see(tk.END)


def main():
    root = tk.Tk()
    app = TrafficAnalyzerGUI(root)
    root.resizable(False, False)
    root.mainloop()

if __name__ == "__main__":
    main()
