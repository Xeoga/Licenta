import tkinter as tk
import threading
import time
import subprocess
import requests
from tkinter import messagebox, filedialog
import tempfile
import os
from core import TrafficAnalyzerCore
from interface_utils import coreleaza_interfete
from graffic_trafic import TrafficGraph
from packet_display import PacketDisplay
from alert_box import AlertBox
from detector import Detector
from scapy.all import rdpcap
import pyperclip

class TrafficAnalyzerGUI:
    def __init__(self, root, username="Guest", uuid=None):
        self.root = root
        self.username = username
        self.user_uuid = uuid
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

        self.filter_help_button = tk.Button(self.bg_frame, text="?", font=("yu gothic ui bold", 12),
                                    command=self.show_filter_examples, bg="#FF5E5E", fg="white", relief="flat", cursor="hand2")
        self.filter_help_button.place(x=420, y=295, width=30, height=30)

        self.graph = TrafficGraph(self.bg_frame)

        self.start_button = tk.Button(self.bg_frame, text="Start Captură", command=self.start_sniffing,
                                      font=("yu gothic ui bold", 12), bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.start_button.place(x=30, y=340, width=180, height=40)

        self.stop_button = tk.Button(self.bg_frame, text="Stop Captură", command=self.stop_sniffing,
                                     font=("yu gothic ui bold", 12), state=tk.DISABLED,
                                     bg="#1D90F5", fg="white", relief="flat", cursor="hand2")
        self.stop_button.place(x=220, y=340, width=180, height=40)

        self.packet_display = PacketDisplay(self.bg_frame)

        self.analyzer = TrafficAnalyzerCore()

        self.packet_display.captured_packets = self.analyzer.captured_packets


        self.packet_rate_label = tk.Label(self.bg_frame, text="📈 Pachete/secundă: 0", font=("yu gothic ui", 12), bg="#272A37", fg="white")
        self.packet_rate_label.place(x=30, y=740)
        self.total_label = tk.Label(self.bg_frame, text="📦 Total pachete: 0", font=("yu gothic ui", 12), bg="#272A37", fg="white")
        self.total_label.place(x=280, y=740)

        self.save_button = tk.Button(self.bg_frame, text="Salvează PCAP", command=self.save_pcap,
                                     font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_button.place(x=30, y=780, width=180, height=40)

        self.save_db_button = tk.Button(self.bg_frame, text="Salvează în DB", command=self.save_to_db,
                                         font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.save_db_button.place(x=220, y=780, width=180, height=40)

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
        self.load_button = tk.Button(self.bg_frame, text="Încarcă PCAP", command=self.load_pcap,
                             font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.load_button.place(x=420, y=780, width=180, height=40)
        self.download_button = tk.Button(self.bg_frame, text="Descarcă din DB", command=self.fetch_pcap_list,
                                 font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.download_button.place(x=620, y=780, width=200, height=40)

        self.report_button = tk.Button(self.bg_frame, text="Generează Raport", command=self.generate_report,
                               font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.report_button.place(x=1340, y=780, width=200, height=40)

        self.discover_button = tk.Button(self.bg_frame, text="Host Discovery", command=self.open_discovery_view,
                                 font=("yu gothic ui bold", 12), bg="#3D404B", fg="white", relief="flat", cursor="hand2")
        self.discover_button.place(x=840, y=780, width=180, height=40)

        self.alert_levels = {
            "CRITICAL": tk.BooleanVar(value=True),
            "WARN": tk.BooleanVar(value=False),
            "INFO": tk.BooleanVar(value=True)
        }

        alert_frame = tk.LabelFrame(self.bg_frame, text="Tipuri Alerte Afișate", bg="#272A37", fg="white", font=("yu gothic ui", 12))
        alert_frame.place(x=977, y=0, width=200, height=120)

        y_offset = 10
        for level, var in self.alert_levels.items():
            cb = tk.Checkbutton(alert_frame, text=level, variable=var, onvalue=True, offvalue=False,
                                font=("yu gothic ui", 10), bg="#272A37", fg="white", activebackground="#272A37", activeforeground="white", selectcolor="#272A37")
            cb.place(x=10, y=y_offset)
            y_offset += 30
    def open_discovery_view(self):
        from network_discovery_view import DiscoveryView
        DiscoveryView(self.root, self.analyzer.report_data)
        
    def update_packet_rate(self):
        if self.running:
            protocol_counts = self.analyzer.get_protocol_counts_and_reset()
            self.packet_rate_label.config(text=f"📈 Pachete/minut: {sum(protocol_counts.values())}")
            self.graph.update_data(protocol_counts)
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

        # 🛠️ Sincronizare necesară pentru follow_stream()
        self.packet_display.captured_packets = self.analyzer.captured_packets
        print(f"[DEBUG] Pachete sincronizate: {len(self.analyzer.captured_packets)} pachete disponibile pentru follow_stream")


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

    def display_packet(self, line):
        self.packet_display.write(line)
    

    def display_packet_counted(self, line):
        self.display_packet(line)
        self.total_packets += 1
        self.total_label.config(text=f"📦 Total pachete: {self.total_packets}")

        alerts = self.detector.process_packet(line)

        for msg, level in alerts:
            if self.alert_levels.get(level, tk.BooleanVar()).get():
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
    def save_to_db(self):
        user_uuid = self.user_uuid

        if not user_uuid:
            self.packet_display.write("⚠️ UUID-ul nu este setat.\n")
            return

        try:
            # Creează fișier temporar
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
                temp_path = temp_file.name
                # Salvează captura în fișierul temporar
                self.analyzer.save_pcap(custom_path=temp_path)

            # Trimite la API
            with open(temp_path, "rb") as file:
                files = {"file": (os.path.basename(temp_path), file, "application/octet-stream")}
                data = {"uuid": user_uuid}
                response = requests.post("http://192.168.1.20:8000/upload_pcap/", data=data, files=files)

            if response.status_code == 200:
                self.packet_display.write("✅ Fișierul a fost salvat în baza de date cu succes.\n")
            else:
                self.packet_display.write(f"❌ Eroare la salvare: {response.status_code} - {response.text}\n")

        except Exception as e:
            self.packet_display.write(f"⚠️ Eroare trimitere API: {e}\n")

        finally:
            # Șterge fișierul temporar
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception as cleanup_error:
                self.packet_display.write(f"⚠️ Eroare la ștergerea fișierului temporar: {cleanup_error}\n")
    def load_pcap(self):
        file_path = filedialog.askopenfilename(
            title="Selectează un fișier PCAP",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if not file_path:
            self.packet_display.write("⚠️ Încărcarea a fost anulată de utilizator.\n")
            return

        try:
            packets = rdpcap(file_path)
            self.packet_display.clear()
            self.analyzer.captured_packets = []

            for pkt in packets:
                self.analyzer.captured_packets.append(pkt)
                summary = self.analyzer.format_packet(pkt)
                self.packet_display.write(summary)
                self.analyzer.classify_and_count(summary)

                protocol_counts = self.core.get_protocol_counts_and_reset()
                self.graph.update_data(protocol_counts)

            self.packet_display.write(f"✅ Încărcat cu succes: {len(packets)} pachete din {file_path}\n")

        except Exception as e:
            self.packet_display.write(f"❌ Eroare la încărcarea fișierului: {e}\n")
    def fetch_pcap_list(self):
        user_uuid = self.user_uuid
        if not user_uuid:
            self.packet_display.write("⚠️ UUID-ul nu este setat.\n")
            return

        try:
            response = requests.get(f"http://192.168.1.20:8000/list_pcaps/{user_uuid}")
            if response.status_code == 200:
                pcap_list = response.json()
                self.show_pcap_selection(pcap_list)
            else:
                self.packet_display.write(f"❌ Eroare API: {response.status_code} - {response.text}\n")
        except Exception as e:
            self.packet_display.write(f"⚠️ Eroare la conectarea la server: {e}\n")
    def show_pcap_selection(self, pcap_list):
        if not pcap_list:
            self.packet_display.write("ℹ️ Nu există fișiere încărcate.\n")
            return

        window = tk.Toplevel()
        window.title("Selectează un fișier PCAP")
        window.geometry("500x300")
        window.configure(bg="#1e1e1e")

        tk.Label(window, text="Selectează un fișier PCAP:", font=("yu gothic ui bold", 12),
                bg="#1e1e1e", fg="white").pack(pady=10)

        listbox = tk.Listbox(window, font=("Consolas", 10), bg="#252526", fg="white", width=60, height=10)
        listbox.pack(pady=10)

        for p in pcap_list:
            listbox.insert(tk.END, p["filename"])

        def on_select():
            index = listbox.curselection()
            if not index:
                return
            selected_file = pcap_list[index[0]]
            self.download_and_load_pcap(selected_file["path"])
            window.destroy()

        tk.Button(window, text="Încarcă fișierul", command=on_select,
                font=("yu gothic ui", 10), bg="#3D404B", fg="white").pack(pady=5)

        tk.Button(window, text="Închide", command=window.destroy,
                font=("yu gothic ui", 10), bg="#007acc", fg="white").pack()
    def show_pcap_selection(self, pcap_list):
        if not pcap_list:
            self.packet_display.write("ℹ️ Nu există fișiere încărcate.\n")
            return

        window = tk.Toplevel()
        window.title("Selectează un fișier PCAP")
        window.geometry("500x300")
        window.configure(bg="#1e1e1e")

        tk.Label(window, text="Selectează un fișier PCAP:", font=("yu gothic ui bold", 12),
                bg="#1e1e1e", fg="white").pack(pady=10)

        listbox = tk.Listbox(window, font=("Consolas", 10), bg="#252526", fg="white", width=60, height=10)
        listbox.pack(pady=10)

        for p in pcap_list:
            listbox.insert(tk.END, p["filename"])

        def on_select():
            index = listbox.curselection()
            if not index:
                return
            selected_file = pcap_list[index[0]]
            self.download_and_load_pcap(selected_file["path"])
            window.destroy()

        tk.Button(window, text="Încarcă fișierul", command=on_select,
                font=("yu gothic ui", 10), bg="#3D404B", fg="white").pack(pady=5)

        tk.Button(window, text="Închide", command=window.destroy,
                font=("yu gothic ui", 10), bg="#007acc", fg="white").pack()
    def download_and_load_pcap(self, remote_path):
        try:
            # API de tip download direct (asigură-te că îl ai definit în FastAPI!)
            url = f"http://192.168.1.20:8000/download_pcap?path={remote_path}"
            response = requests.get(url)

            if response.status_code == 200:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
                    temp_file.write(response.content)
                    temp_path = temp_file.name

                self.packet_display.write(f"📥 Fișier descărcat: {os.path.basename(remote_path)}\n")
                self.load_pcap_file(temp_path)

            else:
                self.packet_display.write(f"❌ Eroare descărcare: {response.status_code} - {response.text}\n")

        except Exception as e:
            self.packet_display.write(f"⚠️ Eroare descărcare fișier: {e}\n")
    from scapy.all import rdpcap

    def load_pcap_file(self, path):
        try:
            packets = rdpcap(path)
            self.packet_display.clear()
            self.analyzer.captured_packets = []

            for pkt in packets:
                self.analyzer.captured_packets.append(pkt)
                summary = self.analyzer.format_packet(pkt)
                self.packet_display.write(summary)
                self.analyzer.classify_and_count(summary)

            self.graph.update_data(
                self.analyzer.tcp_count,
                self.analyzer.udp_count,
                self.analyzer.other_count
            )
            self.packet_display.write(f"✅ Fișier încărcat local: {len(packets)} pachete.\n")
        except Exception as e:
            self.packet_display.write(f"❌ Eroare încărcare fișier: {e}\n")

    def show_filter_examples(self):
        window = tk.Toplevel()
        window.title("Exemple filtre BPF")
        window.geometry("700x600")
        window.configure(bg="#1e1e1e")

        examples = [
            "tcp                               → doar trafic TCP",
            "udp                               → doar trafic UDP",
            "icmp                              → doar pachete ICMP (ping)",
            "port 80                           → tot traficul pe portul 80",
            "tcp port 443                      → conexiuni HTTPS",
            "udp port 53                       → cereri DNS",
            "src host 192.168.1.1              → trafic de la un IP anume",
            "dst port 22                       → SSH trafic primit",
            "tcp and port 21                   → conexiuni FTP",
            "not arp                           → exclude pachetele ARP",
            "src net 192.168.0.0/16            → rețea sursă întreagă",
            "dst net 10.0.0.0/8                → rețea destinație mare",
            "ip                                → doar pachete IP (exclude ARP etc)",
            "tcp dst port range 20-30          → porturi TCP între 20 și 30",
            "udp and not port 123              → exclude NTP (port 123)",
            "host 8.8.8.8                      → pachete de la/sau către 8.8.8.8",
            "tcp[tcpflags] & tcp-syn != 0      → doar SYN-uri inițiale",
            "tcp[tcpflags] & tcp-ack != 0      → doar ACK-uri",
            "ether src 00:11:22:33:44:55       → MAC sursă specific",
            "tcp[13] = 18                      → SYN + ACK (handshake acceptat)",
            "tcp[13] & 2 != 0                  → detectare SYN",
            "dst net 192.168.1.0 mask 255.255.255.0  → rețea locală",
            "tcp src port 443 and dst port 80  → redirecționare suspectă",
            "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0) → HTTP payload",
            "tcp src portrange 1000-2000       → trafic ieșit din porturi intermediare",
            "udp portrange 60000-65535         → atacuri de tip reflection?",
            "tcp[13] & 4 != 0                  → pachete RST (conexiuni resetate)",
            "ip proto \\tcp                    → doar TCP cu escape",
            "tcp and not port 22               → TCP dar exclude SSH",
            "not (src net 192.168.1.0/24)      → exclude rețeaua locală",
            "ip src 192.168.1.3 and ip dst 8.8.8.8 → trafic direct între două IP-uri"
        ]

        tk.Label(window, text="Exemple de filtre pentru captură rețea", font=("yu gothic ui bold", 14),
                bg="#1e1e1e", fg="white").pack(pady=10)

        listbox = tk.Listbox(window, font=("Consolas", 11), bg="#2e2e2e", fg="white",
                            width=90, height=25, selectbackground="#007acc", selectforeground="white")
        listbox.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        for ex in examples:
            listbox.insert(tk.END, ex)

        def copy_selected(event):
            selection = listbox.curselection()
            if selection:
                selected_text = listbox.get(selection[0]).split("→")[0].strip()
                pyperclip.copy(selected_text)
                self.packet_display.write(f"📋 Filtru copiat: {selected_text}\n")
                self.filter_entry.delete(0, tk.END)
                self.filter_entry.insert(0, selected_text)

        listbox.bind("<Double-Button-1>", copy_selected)

        tk.Button(window, text="Închide", command=window.destroy,
                font=("yu gothic ui", 10), bg="#007acc", fg="white").pack(pady=10)
        
    def generate_report(self):
        try:
            self.analyzer.report_data.export_json("raport_statistic.json")
            self.analyzer.report_data.export_pdf_report("raport_final.pdf")

            self.packet_display.write("📊 Raport generat cu succes:\n")
            self.packet_display.write(" - raport_statistic.json\n")
            self.packet_display.write(" - raport_final.pdf\n")

            messagebox.showinfo("Raport Generat", "Raportul a fost salvat în directorul curent.")
        except Exception as e:
            self.packet_display.write(f"❌ Eroare la generarea raportului: {e}\n")
            messagebox.showerror("Eroare", f"Eroare la generarea raportului:\n{e}")

