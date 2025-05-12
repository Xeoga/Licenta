import tkinter as tk
from tkinter import messagebox, filedialog
import re
from scapy.all import wrpcap, hexdump

import tkinter as tk
from tkinter import messagebox, filedialog
import re
from scapy.all import wrpcap, hexdump

class PacketDisplay:
    def __init__(self, parent_frame):
        print("[DEBUG] Initializare PacketDisplay")
        self.border_frame = tk.Frame(parent_frame, bg="#5A5A5A", bd=2, relief="ridge")
        self.border_frame.place(x=30, y=390, relwidth=0.6, height=350)

        self.content_frame = tk.Frame(self.border_frame, bg="#5A5A5A")
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        self.text_widget = tk.Text(
            self.content_frame, bg="#1E1E1E", fg="white",
            font=("Consolas", 10), insertbackground="white",
            wrap="word", bd=0
        )
        self.text_widget.pack(fill=tk.BOTH, expand=True)

        self.search_frame = tk.Frame(self.border_frame, bg="#3A3A3A")
        self.search_frame.pack(fill="x", pady=4)

        tk.Label(self.search_frame, text="📍 ID pachet:", bg="#3A3A3A", fg="white",
                 font=("yu gothic ui", 9)).pack(side="left", padx=(5, 0))

        self.packet_id_entry = tk.Entry(self.search_frame, width=6)
        self.packet_id_entry.pack(side="left", padx=5)

        tk.Button(self.search_frame, text="Găsește", command=self.find_and_jump_to_packet,
                  font=("yu gothic ui", 9), bg="#1D90F5", fg="white").pack(side="left", padx=5)

        tk.Button(self.search_frame, text="🔎 Detalii", command=self.show_packet_details_from_entry,
                  font=("yu gothic ui", 9), bg="#007acc", fg="white").pack(side="left", padx=5)

        self.text_widget.bind("<Button-3>", self.on_right_click)

        self.packets = []
        self.selected_index = None
        self.packet_comments = {}
        self.captured_packets = None
        self.packet_map = {}
        self.stream_window = None

    def find_packet_by_id(self, packet_id: int):
        try:
            if not self.captured_packets:
                raise ValueError("Nu există pachete capturate.")
            if packet_id < 1 or packet_id > len(self.captured_packets):
                raise IndexError(f"Pachetul #{packet_id} nu există.")
            return self.captured_packets[packet_id - 1]
        except Exception as e:
            messagebox.showerror("Eroare", f"Eroare la găsirea pachetului: {e}")
            return None

    def jump_to_packet(self, packet_id: int):
        try:
            self.text_widget.see(f"{packet_id}.0")
            self.text_widget.tag_remove("highlight", "1.0", tk.END)
            self.text_widget.tag_add("highlight", f"{packet_id}.0", f"{packet_id}.end")
            self.text_widget.tag_config("highlight", background="#007acc")
        except Exception as e:
            messagebox.showerror("Eroare", f"Nu s-a putut accesa pachetul #{packet_id}: {e}")

    def find_and_jump_to_packet(self):
        try:
            pkt_id = int(self.packet_id_entry.get())
            pkt = self.find_packet_by_id(pkt_id)
            if pkt:
                self.jump_to_packet(pkt_id)
                messagebox.showinfo("Găsit", f"Pachetul #{pkt_id} a fost localizat.")
            else:
                messagebox.showwarning("Negăsit", f"Pachetul #{pkt_id} nu există.")
        except ValueError:
            messagebox.showerror("Eroare", "ID-ul introdus nu este valid.")

    def show_packet_details_from_entry(self):
        try:
            pkt_id = int(self.packet_id_entry.get())
            if pkt_id < 1 or pkt_id > len(self.packets):
                raise IndexError("ID invalid.")
            content = self.packets[pkt_id - 1]
            self.show_packet_details(content, packet_id=pkt_id)
        except Exception as e:
            messagebox.showerror("Eroare", f"Nu se pot afișa detaliile: {e}")

    def write(self, line, packet_obj=None):
        packet_index = len(self.packets) + 1
        self.packets.append(line)
        if packet_obj:
            self.packet_map[packet_index] = packet_obj
        prefix = "💬 " if packet_index in self.packet_comments else ""
        self.text_widget.insert(tk.END, prefix + line)
        self.text_widget.see(tk.END)

    def clear(self):
        self.packets.clear()
        self.text_widget.delete("1.0", tk.END)
        self.packet_comments.clear()

    def on_right_click(self, event):
        index = self.text_widget.index(f"@{event.x},{event.y}")
        line_number = int(str(index).split(".")[0])

        if line_number - 1 >= len(self.packets):
            print(f"[DEBUG] Click dreapta pe linie inexistentă: {line_number}")
            return

        self.selected_index = line_number
        print(f"[DEBUG] Click dreapta - selectat pachet #{self.selected_index}")

        menu = tk.Menu(self.text_widget, tearoff=0, bg="#2E2E2E", fg="white", activebackground="#007acc")
        menu.add_command(label="🔎 Detalii pachet", command=self.show_selected_packet_details)
        menu.add_command(label="📁 Exportă pachet", command=self.export_selected_packet)
        menu.add_command(label="🚩 Marchează ca suspect", command=self.mark_as_suspect)
        menu.add_command(label="🔁 Urmărește fluxul", command=self.follow_stream)
        menu.add_command(label="✏️ Adaugă comentariu", command=self.add_comment_to_packet)
        menu.add_command(label="🔍 Afișează date transmise (Raw)", command=self.show_raw_data)
        menu.tk_popup(event.x_root, event.y_root)


    def show_selected_packet_details(self):
        if self.selected_index is None or self.selected_index - 1 >= len(self.packets):
            messagebox.showwarning("Eroare", "Nu a fost selectat niciun pachet valid.")
            return
        content = self.packets[self.selected_index - 1]
        self.show_packet_details(content, packet_id=self.selected_index)

    def export_selected_packet(self):
        if self.captured_packets is None:
            messagebox.showwarning("Export imposibil", "Nu există pachete capturate pentru export.")
            return

        if self.selected_index is None or self.selected_index - 1 >= len(self.captured_packets):
            messagebox.showwarning("Export imposibil", "Index pachet invalid.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")],
            title="Salvează pachetul"
        )

        if file_path:
            try:
                wrpcap(file_path, [self.captured_packets[self.selected_index - 1]])
                messagebox.showinfo("Export reușit", f"Pachetul a fost salvat în:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Eroare", f"Exportul a eșuat: {str(e)}")

    def follow_stream(self):
        if self.stream_window and self.stream_window.winfo_exists():
            self.stream_window.lift()
            return

        if not self.captured_packets or self.selected_index is None:
            messagebox.showwarning("Eroare", "Nu există pachet valid pentru a urmări fluxul.")
            return

        try:
            packet = self.captured_packets[self.selected_index - 1]
        except IndexError:
            messagebox.showerror("Eroare", "Index pachet invalid.")
            return

        if not packet.haslayer("IP") or not (packet.haslayer("TCP") or packet.haslayer("UDP")):
            messagebox.showinfo("Flux indisponibil", "Pachetul nu este TCP/UDP sau nu are layer IP.")
            return

        ip_layer = packet["IP"]
        proto_layer = packet["TCP"] if packet.haslayer("TCP") else packet["UDP"]

        ip_src, ip_dst = ip_layer.src, ip_layer.dst
        port_src, port_dst = proto_layer.sport, proto_layer.dport
        protocol = "TCP" if packet.haslayer("TCP") else "UDP"

        matched, indices = [], []
        for idx, pkt in enumerate(self.captured_packets, 1):
            if not pkt.haslayer("IP") or not (pkt.haslayer("TCP") or pkt.haslayer("UDP")):
                continue
            p_ip, p_proto = pkt["IP"], pkt["TCP"] if pkt.haslayer("TCP") else pkt["UDP"]
            try:
                if (p_ip.src, p_ip.dst, p_proto.sport, p_proto.dport) == (ip_src, ip_dst, port_src, port_dst) or \
                (p_ip.src, p_ip.dst, p_proto.sport, p_proto.dport) == (ip_dst, ip_src, port_dst, port_src):
                    matched.append(pkt)
                    indices.append(idx)
            except Exception:
                continue

        if not matched:
            messagebox.showinfo("Flux gol", "Nu s-au găsit pachete în același flux.")
            return

        self.stream_window = tk.Toplevel()
        win = self.stream_window
        win.title(f"🔁 Flux {protocol}")
        win.configure(bg="#1e1e1e")
        win.geometry("1000x700")

        tk.Label(win, text=f"Flux {protocol} între {ip_src}:{port_src} ↔ {ip_dst}:{port_dst}",
                font=("yu gothic ui bold", 12), bg="#1e1e1e", fg="white").pack(pady=10)

        txt = tk.Text(win, bg="#252526", fg="white", font=("Consolas", 10), wrap="none", relief="flat")
        for pkt in matched:
            txt.insert(tk.END, pkt.summary() + "\n")
        txt.config(state="disabled")
        txt.pack(padx=10, pady=5, expand=True, fill="both")

        def show_raw_for_stream():
            raw_win = tk.Toplevel()
            raw_win.title("Raw Data (Hexdump) pentru flux")
            raw_win.configure(bg="#1e1e1e")
            raw_win.geometry("1000x700")

            raw_text = tk.Text(raw_win, bg="#1e1e1e", fg="white", font=("Consolas", 10), wrap="none", relief="flat")
            for pkt in matched:
                try:
                    dump = hexdump(pkt, dump=True)
                    raw_text.insert(tk.END, dump + "\n\n")
                except Exception as e:
                    raw_text.insert(tk.END, f"[Eroare dump pachet]: {e}\n")
            raw_text.config(state="disabled")
            raw_text.pack(padx=10, pady=10, fill="both", expand=True)

            tk.Button(raw_win, text="Închide", command=raw_win.destroy, bg="#007acc", fg="white").pack(pady=5)

        def show_payload_for_stream():
            payload_win = tk.Toplevel()
            payload_win.title("Payload-uri pentru flux")
            payload_win.configure(bg="#1e1e1e")
            payload_win.geometry("1000x700")

            payload_text = tk.Text(payload_win, bg="#1e1e1e", fg="white",
                                font=("Consolas", 10), wrap="none", relief="flat")
            for i, pkt in enumerate(matched, 1):
                if pkt.haslayer("Raw"):
                    raw_data = pkt["Raw"].load
                    try:
                        decoded = raw_data.decode('utf-8', errors="replace")
                        payload_text.insert(tk.END, f"[Pachet #{i}]\n{decoded}\n\n")
                    except Exception as e:
                        payload_text.insert(tk.END, f"[Pachet #{i}] [Eroare decodare payload]: {e}\n\n")
                else:
                    payload_text.insert(tk.END, f"[Pachet #{i}] [Fără payload disponibil]\n\n")
            payload_text.config(state="disabled")
            payload_text.pack(padx=10, pady=10, fill="both", expand=True)

            tk.Button(payload_win, text="Închide", command=payload_win.destroy, bg="#007acc", fg="white").pack(pady=5)

        def mark_stream_as_suspect():
            for idx in indices:
                try:
                    line_start, line_end = f"{idx}.0", f"{idx}.end"
                    current_line = self.text_widget.get(line_start, line_end)
                    if not current_line.startswith("🚩"):
                        self.text_widget.delete(line_start, line_end)
                        self.text_widget.insert(line_start, "🚩 " + current_line)
                    tag_name = f"suspect_{idx}"
                    self.text_widget.tag_add(tag_name, line_start, line_end)
                    self.text_widget.tag_config(tag_name, background="#660000", foreground="white")
                except Exception as e:
                    print(f"[DEBUG] Eroare marcare flux #{idx}: {e}")

        def export_stream_to_pcap():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap")],
                title="Salvează fluxul în PCAP"
            )
            if file_path:
                try:
                    wrpcap(file_path, matched)
                    messagebox.showinfo("Export reușit", f"Fluxul a fost salvat în:\n{file_path}")
                except Exception as e:
                    messagebox.showerror("Eroare", f"Eroare la export: {e}")

        tk.Button(win, text="Afișează Raw Data pentru flux", command=show_raw_for_stream,
                bg="#3D404B", fg="white").pack(pady=5)

        tk.Button(win, text="📦 Afișează doar Payload-ul", command=show_payload_for_stream,
                bg="#6C5CE7", fg="white").pack(pady=5)

        tk.Button(win, text="🚩 Marchează fluxul ca suspect", command=mark_stream_as_suspect,
                bg="#FF3B30", fg="white").pack(pady=5)

        tk.Button(win, text="💾 Salvează fluxul în PCAP", command=export_stream_to_pcap,
                bg="#00B894", fg="white").pack(pady=5)

        tk.Button(win, text="Închide", command=win.destroy,
                bg="#007acc", fg="white").pack(pady=5)

        
    def show_raw_data(self):
        if self.captured_packets is None or self.selected_index - 1 >= len(self.captured_packets):
            messagebox.showwarning("Eroare", "Nu există pachet valid pentru a afișa datele brute.")
            return

        packet = self.captured_packets[self.selected_index - 1]
        raw_output = hexdump(packet, dump=True)

        window = tk.Toplevel()
        window.title("🔍 Date brute transmise")
        window.configure(bg="#1e1e1e")
        window.geometry("620x400")

        tk.Label(window, text="Raw Data (Hexdump)", bg="#1e1e1e", fg="white",
                 font=("yu gothic ui bold", 14)).pack(pady=10)

        text = tk.Text(window, bg="#252526", fg="white", font=("Consolas", 10),
                       wrap="none", relief="flat")
        text.insert("1.0", raw_output)
        text.config(state="disabled")
        text.pack(padx=10, pady=5, expand=True, fill="both")

        tk.Button(window, text="Închide", command=window.destroy,
                  bg="#007acc", fg="white").pack(pady=5)
    def mark_as_suspect(self):
        if self.selected_index is None:
            return

        try:
            line_start = f"{self.selected_index}.0"
            line_end = f"{self.selected_index}.end"
            current_line = self.text_widget.get(line_start, line_end)

            # Evită dublarea simbolului
            if not current_line.startswith("🚩"):
                self.text_widget.delete(line_start, line_end)
                self.text_widget.insert(line_start, "🚩 " + current_line)

            # Aplică tag vizual
            tag_name = f"suspect_{self.selected_index}"
            self.text_widget.tag_add(tag_name, line_start, line_end)
            self.text_widget.tag_config(tag_name, background="#660000", foreground="white")

        except Exception as e:
            print(f"[DEBUG] Eroare la marcare suspect: {e}")
    def add_comment_to_packet(self):
        if not self.selected_index:
            return

        comment_window = tk.Toplevel()
        comment_window.title("Adaugă comentariu")
        comment_window.configure(bg="#1e1e1e")
        comment_window.geometry("400x200")

        tk.Label(comment_window, text="Comentariu pentru pachetul #" + str(self.selected_index),
                 bg="#1e1e1e", fg="white", font=("yu gothic ui bold", 12)).pack(pady=10)

        text = tk.Text(comment_window, height=5, bg="#252526", fg="white", font=("Consolas", 10))
        text.pack(padx=10, pady=10)

        def save_comment():
            msg = text.get("1.0", tk.END).strip()
            self.packet_comments[self.selected_index] = msg
            messagebox.showinfo("Salvat", "Comentariul a fost salvat.")
            comment_window.destroy()

            try:
                current_line = self.text_widget.get(f"{self.selected_index}.0", f"{self.selected_index}.end")
                if not current_line.startswith("💬"):
                    self.text_widget.delete(f"{self.selected_index}.0", f"{self.selected_index}.end")
                    self.text_widget.insert(f"{self.selected_index}.0", "💬 " + current_line)
            except Exception as e:
                print(f"[DEBUG] Eroare adăugare iconiță: {e}")

        tk.Button(comment_window, text="💾 Salvează", command=save_comment,
                  bg="#3D404B", fg="white", font=("yu gothic ui", 10)).pack(pady=5)

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
        comment = self.packet_comments.get(packet_id)
        if comment:
            body += f"\n\n📝 Comentariu: {comment}"

        full_text = f"{header}\n\n{body}"

        window = tk.Toplevel()
        window.title("🧾 Detalii pachet")
        window.configure(bg="#1e1e1e")
        window.geometry("460x360")
        window.resizable(False, False)

        tk.Label(window, text="Detalii pachet", font=("yu gothic ui bold", 14),
                 bg="#1e1e1e", fg="white").pack(pady=10)

        text = tk.Text(window, height=14, width=50, bg="#252526", fg="white",
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
