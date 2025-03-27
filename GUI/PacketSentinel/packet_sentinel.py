import tkinter as tk
import threading
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from scapy.utils import wrpcap
import wmi
import re

class PacketSentinel:
    def __init__(self, parent, output_callback):
        self.frame = tk.Frame(parent, bg="#272A37")
        self.frame.place(x=0, y=180, width=1060, height=560)

        tk.Label(self.frame, text="Selectează interfața:", font=("yu gothic ui bold", 14),
                 bg="#272A37", fg="white").place(x=30, y=10)

        self.output_callback = output_callback

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
        self.interface_menu = tk.OptionMenu(self.frame, self.selected_interface, *self.interfaces)
        self.interface_menu.config(bg="#3D404B", fg="white", font=("yu gothic ui", 12), width=30)
        self.interface_menu["menu"].config(bg="#3D404B", fg="white")
        self.interface_menu.place(x=30, y=40)

        self.start_button = tk.Button(self.frame, text="Start Captură", command=self.start_sniffing,
                                      font=("yu gothic ui bold", 12), bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.start_button.place(x=30, y=90, width=180, height=40)

        self.stop_button = tk.Button(self.frame, text="Stop Captură", command=self.stop_sniffing,
                                     font=("yu gothic ui bold", 12), state=tk.DISABLED, bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.stop_button.place(x=220, y=90, width=180, height=40)

        self.save_button = tk.Button(self.frame, text="Salvează PCAP", command=self.save_pcap,
                                     font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_button.place(x=30, y=140, width=180, height=40)

        self.save_txt_button = tk.Button(self.frame, text="Salvează TXT", command=self.save_txt,
                                         font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_txt_button.place(x=220, y=140, width=180, height=40)

        self.output_text = tk.Text(self.frame, bg="#1E1E1E", fg="white", font=("Consolas", 10),
                                   insertbackground="white", wrap="word", bd=0)
        self.output_text.place(x=30, y=200, width=1000, height=320)

        self.sniffing_thread = None
        self.stop_sniff = False
        self.captured_packets = []

    def start_sniffing(self):
        self.stop_sniff = False
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffing_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffing_thread.start()
        self.log("🟢 Captură începută...")

    def stop_sniffing(self):
        self.stop_sniff = True
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("🔴 Captură oprită.")

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
            self.log(info)
            self.captured_packets.append(packet)

    def save_pcap(self):
        if self.captured_packets:
            wrpcap("captura_trafic.pcap", self.captured_packets)
            self.log("💾 PCAP salvat ca captura_trafic.pcap")
        else:
            self.log("⚠️ Nu există pachete capturate.")

    def save_txt(self):
        with open("captura_trafic.txt", "w") as file:
            for packet in self.captured_packets:
                file.write(str(packet) + "\n")
        self.log("💾 TXT salvat ca captura_trafic.txt")

    def log(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        if self.output_callback:
            self.output_callback(message)

    def show(self):
        self.frame.place(x=0, y=180, width=1060, height=560)

    def hide(self):
        self.frame.place_forget()