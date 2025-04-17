import tkinter as tk
from tkinter import messagebox
import re

class PacketDisplay:
    def __init__(self, parent_frame):
        # Cadru cu bordură pentru zona de afișare a pachetelor
        self.border_frame = tk.Frame(parent_frame, bg="#5A5A5A", bd=2, relief="ridge")  # default grey
        self.border_frame.place(x=30, y=390, relwidth=0.6, height=350)

        # Text widget plasat în interiorul bordurii
        self.text_widget = tk.Text(
            self.border_frame, bg="#1E1E1E", fg="white",
            font=("Consolas", 10), insertbackground="white",
            wrap="word", bd=0
        )
        self.text_widget.pack(fill=tk.BOTH, expand=True)

        self.text_widget.bind("<Button-1>", self.on_click)
        self.packets = []

    def write(self, line):
        self.packets.append(line)
        self.text_widget.insert(tk.END, line)
        self.text_widget.see(tk.END)

    def clear(self):
        self.packets.clear()
        self.text_widget.delete("1.0", tk.END)

    def on_click(self, event):
        index = self.text_widget.index(f"@{event.x},{event.y}")
        line_number = int(str(index).split(".")[0])
        try:
            content = self.packets[line_number - 1]
        except IndexError:
            return
        self.show_packet_details(content, packet_id=line_number)

    def show_packet_details(self, content, packet_id=None):
        details = {}
        ip_src = ip_dst = port_src = port_dst = protocol = time = None

        time_match = re.match(r"^\s*(\d{2}:\d{2}:\d{2}\.\d{3})", content)
        if time_match:
            time = time_match.group(1)
            details["⏱️ Timp"] = time

        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})", content)
        if ip_match:
            ip_src = ip_match.group(1)
            ip_dst = ip_match.group(2)
            details["🖥️ IP Sursă"] = ip_src
            details["🌐 IP Destinație"] = ip_dst

        port_proto_match = re.search(r"(\d+)\s*→\s*(\d+)\s*\[([A-Z0-9]+)?\]", content)
        if port_proto_match:
            port_src = port_proto_match.group(1)
            port_dst = port_proto_match.group(2)
            protocol = port_proto_match.group(3)
            details["📤 Port Sursă"] = port_src
            details["📥 Port Destinație"] = port_dst
            details["📡 Protocol"] = protocol
        else:
            proto_match = re.search(r"\[([A-Z0-9]+)\]", content)
            if proto_match:
                protocol = proto_match.group(1)
                details["📡 Protocol"] = protocol

        if "DNS" in content.upper():
            details["🧠 Info"] = "DNS query sau response"
        elif "HTTP" in content.upper():
            details["🧠 Info"] = "HTTP request sau răspuns"
        elif "ICMP" in content.upper():
            details["🧠 Info"] = "ICMP / Ping"
        elif "ARP" in content.upper():
            details["🧠 Info"] = "ARP (adresă MAC/IP)"

        header = f"🧾 ID #{packet_id or '?'} — "
        if ip_src and ip_dst:
            header += f"{ip_src}:{port_src or '?'} → {ip_dst}:{port_dst or '?'} [{protocol or '?'}]"
        if time:
            header += f" @ {time}"

        body = "\n".join(f"{k:<20}: {v}" for k, v in details.items() if v)
        full_text = f"{header}\n\n{body}"

        window = tk.Toplevel()
        window.title("🧾 Detalii pachet")
        window.configure(bg="#1e1e1e")
        window.geometry("460x330")
        window.resizable(False, False)

        tk.Label(window, text="Detalii pachet", font=("yu gothic ui bold", 14),
                 bg="#1e1e1e", fg="white").pack(pady=10)

        text = tk.Text(window, height=12, width=50, bg="#252526", fg="white",
                       font=("Consolas", 10), wrap="word", relief="flat", borderwidth=0)
        text.insert("1.0", full_text)
        text.config(state="disabled")
        text.pack(padx=20, pady=5)

        tk.Button(window, text="📋 Copiază", command=lambda: self.copy_to_clipboard(window, full_text),
                  bg="#3D404B", fg="white", font=("yu gothic ui", 10),
                  relief="flat", cursor="hand2").pack(pady=3)

        tk.Button(window, text="Închide", command=window.destroy,
                  bg="#007acc", fg="white", font=("yu gothic ui", 10, "bold"),
                  relief="flat", cursor="hand2").pack(pady=3)

    def copy_to_clipboard(self, window, text):
        window.clipboard_clear()
        window.clipboard_append(text)
        window.update()

    def set_border_color(self, color):
        self.border_frame.configure(bg=color)

    def get_widget(self):
        return self.text_widget
