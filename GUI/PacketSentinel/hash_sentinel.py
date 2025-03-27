import tkinter as tk
from tkinter import filedialog, messagebox
import datetime
import subprocess
import threading
import os
import shutil
import uuid
import sys

sys.stdout.reconfigure(encoding='utf-8')

HASH_OPTIONS = [
    "auto", "md5", "sha1", "sha256", "sha512",
    "bcrypt", "NTLM", "MySQL323", "MySQLSHA1", "WordPress", "Drupal7"
    ]

class HashSentinel:
    def __init__(self, parent):
        self.frame = tk.Frame(parent, bg="#272A37")
        self.frame.place(x=0, y=180, width=1060, height=560)
        self.frame.place_forget()

        entry_width = 25

        tk.Label(self.frame, text="Introduceți hash-ul:", font=("yu gothic ui", 12), bg="#272A37", fg="white").place(x=40, y=20)
        self.hash_entry = tk.Entry(self.frame, font=("yu gothic ui", 12), width=entry_width)
        self.hash_entry.place(x=40, y=50)

        tk.Button(self.frame, text="Încarcă Wordlist", command=self.browse_wordlist,
                font=("yu gothic ui bold", 11), bg="#3D404B", fg="white", relief=tk.FLAT, cursor="hand2").place(x=700, y=45, width=200, height=30)
        tk.Button(self.frame, text="Selectează Wordlist", command=self.select_wordlist,
                font=("yu gothic ui bold", 11), bg="#3D404B", fg="white", relief=tk.FLAT, cursor="hand2").place(x=700, y=10, width=200, height=30)

        self.wordlist_path = tk.StringVar()
        self.wordlist_label = tk.Label(self.frame, textvariable=self.wordlist_path, font=("yu gothic ui", 10),
                                       bg="#272A37", fg="white", wraplength=250, justify="left")
        self.wordlist_label.place(x=700, y=80)



        tk.Label(self.frame, text="Tip hash:", font=("yu gothic ui", 12), bg="#272A37", fg="white").place(x=40, y=110)
        self.hash_type = tk.StringVar(value="auto")
        self.hash_type_menu = tk.OptionMenu(self.frame, self.hash_type, *HASH_OPTIONS)
        self.hash_type_menu.config(bg="#3D404B", fg="white", font=("yu gothic ui", 12), width=entry_width)
        self.hash_type_menu["menu"].config(bg="#3D404B", fg="white")
        self.hash_type_menu.place(x=40, y=140)
        tk.Button(self.frame, text="🔍", command=self.detect_hash_type,
          font=("yu gothic ui bold", 11), bg="#1D90F5", fg="white", relief=tk.FLAT, cursor="hand2"
          ).place(x=300, y=140, width=50)



        tk.Label(self.frame, text="Tip atac:", font=("yu gothic ui", 12), bg="#272A37", fg="white").place(x=360, y=110)
        self.attack_mode = tk.StringVar(value="wordlist")
        self.attack_mode_menu = tk.OptionMenu(self.frame, self.attack_mode, "wordlist", "bruteforce")
        self.attack_mode_menu.config(bg="#3D404B", fg="white", font=("yu gothic ui", 12), width=entry_width)
        self.attack_mode_menu["menu"].config(bg="#3D404B", fg="white")
        self.attack_mode_menu.place(x=360, y=140)

        self.ram_mode = tk.BooleanVar(value=False)
        self.ram_radiobuttons = []

        tk.Label(self.frame, text="Mod acces wordlist:", font=("yu gothic ui", 12), bg="#272A37", fg="white").place(x=40, y=280)
        rb1 = tk.Radiobutton(self.frame, text="Fișier direct", variable=self.ram_mode, value=False,
                    bg="#272A37", fg="white", selectcolor="#272A37", font=("yu gothic ui", 11))
        rb1.place(x=40, y=310)
        rb2 = tk.Radiobutton(self.frame, text="În RAM (rapid)", variable=self.ram_mode, value=True,
                    bg="#272A37", fg="white", selectcolor="#272A37", font=("yu gothic ui", 11))
        rb2.place(x=180, y=310)
        self.ram_radiobuttons.extend([rb1, rb2])


        tk.Label(self.frame, text="Charset (brute-force):", font=("yu gothic ui", 12), bg="#272A37", fg="white").place(x=700, y=110)
        self.charset_entry = tk.Entry(self.frame, font=("yu gothic ui", 12), width=entry_width)
        self.charset_entry.insert(0, "abc123")
        self.charset_entry.place(x=700, y=140)

        tk.Label(self.frame, text="Lungime maximă:", font=("yu gothic ui", 12), bg="#272A37", fg="white").place(x=40, y=200)
        self.maxlen_entry = tk.Entry(self.frame, font=("yu gothic ui", 12), width=entry_width)
        self.maxlen_entry.insert(0, "4")
        self.maxlen_entry.place(x=40, y=230)

        tk.Label(self.frame, text="Threaduri:", font=("yu gothic ui", 12), bg="#272A37", fg="white").place(x=360, y=200)
        self.threads_entry = tk.Entry(self.frame, font=("yu gothic ui", 12), width=entry_width)
        self.threads_entry.insert(0, "4")
        self.threads_entry.place(x=360, y=230)

        tk.Button(self.frame, text="Start Atac", command=self.start_attack,
                  font=("yu gothic ui bold", 12), bg="#1D90F5", fg="white", relief="flat", cursor="hand2").place(x=700, y=230, width=200, height=40)
        
        self.attack_mode.trace_add("write", self.update_ui_for_mode)
        self.update_ui_for_mode()

    def browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            os.makedirs("wordlists", exist_ok=True)
            original_filename = os.path.basename(path)
            persistent_path = os.path.join("wordlists", original_filename)

            # Copiază doar dacă nu e deja acolo
            if os.path.abspath(path) != os.path.abspath(persistent_path):
                shutil.copyfile(path, persistent_path)

            self.wordlist_path.set(persistent_path)

    
    def select_wordlist(self):
        folder_path = "wordlists"
        os.makedirs(folder_path, exist_ok=True)
        files = [f for f in os.listdir(folder_path) if f.endswith(".txt")]

        if not files:
            messagebox.showinfo("Wordlists", "Nu există wordlist-uri disponibile.")
            return

        def set_selected():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("Atenție", "Selectează un fișier din listă.")
                return

            selected_file = listbox.get(selection[0])
            source_path = os.path.join(folder_path, selected_file)
            os.makedirs("wordlists", exist_ok=True)
            persistent_path = os.path.join("wordlists", selected_file)

            # Dacă fișierul nu e deja acolo (sau e din alt loc), copiază-l
            if os.path.abspath(source_path) != os.path.abspath(persistent_path):
                try:
                    shutil.copyfile(source_path, persistent_path)
                    print(f"[INFO] Wordlist copiat în: {persistent_path}")
                except Exception as e:
                    messagebox.showerror("Eroare", f"Eroare la copierea wordlistului: {e}")
                    return

            self.wordlist_path.set(persistent_path)
            print(f"[INFO] Wordlist selectat: {persistent_path}")
            top.destroy()


        top = tk.Toplevel(self.frame)
        top.title("Selectează Wordlist")
        top.geometry("400x350+400+200")
        top.configure(bg="#1E1E1E")
        top.grab_set()  # face fereastra modală

        tk.Label(top, text="Alege un wordlist:", bg="#1E1E1E", fg="white", font=("yu gothic ui", 12)).pack(pady=10)

        listbox = tk.Listbox(top, font=("yu gothic ui", 11), bg="#2E2E2E", fg="white", selectbackground="#1D90F5")
        for file in files:
            listbox.insert(tk.END, file)
        listbox.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        # ➕ Selectare prin dublu-click
        def on_double_click(event):
            set_selected()
        listbox.bind("<Double-Button-1>", on_double_click)

        # ✅ Butonul care lipsea
        select_btn = tk.Button(top, text="Selectează", command=set_selected,
                            font=("yu gothic ui bold", 11), bg="#1D90F5", fg="white")
        select_btn.pack(pady=10)

    def detect_hash_type(self):
        hash_value = self.hash_entry.get().strip()
        if not hash_value:
            messagebox.showwarning("Atenție", "Introduceți un hash.")
            return

        args = [
            os.path.join(os.path.dirname(__file__), "bruteforce_cli.exe"),
            "--hash", hash_value,
            "--detect-only"
        ]

        def run_detect():
            try:
                result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8')
                detected_output = result.stdout.strip()
                lines = [line.strip() for line in detected_output.splitlines() if line.strip()]

                if not lines or lines[-1] == "unknown":
                    messagebox.showwarning("Rezultat", "Hash necunoscut.")
                    return
                
                raw_options = [line.lstrip("- ").strip() for line in lines if not line.lower().startswith("detectare")]
                hash_options = list(dict.fromkeys(raw_options))  # elimină duplicatele, păstrând ordinea


                if len(hash_options) == 1:
                    self.hash_type.set(hash_options[0])
                    messagebox.showinfo("Detectare hash", f"Tip detectat: {hash_options[0]}")
                else:
                    # alegere din listă
                    def set_choice():
                        sel = listbox.curselection()
                        if not sel:
                            messagebox.showwarning("Atenție", "Selectează un tip de hash.")
                            return
                        choice = listbox.get(sel[0])
                        self.hash_type.set(choice)
                        top.destroy()

                    top = tk.Toplevel(self.frame)
                    top.title("Alege tipul hashului")
                    top.geometry("300x250+400+300")
                    top.configure(bg="#1E1E1E")
                    top.grab_set()

                    tk.Label(top, text="Mai multe opțiuni detectate:", bg="#1E1E1E", fg="white",
                            font=("yu gothic ui", 11)).pack(pady=10)

                    listbox = tk.Listbox(top, font=("yu gothic ui", 11), bg="#2E2E2E", fg="white", selectbackground="#1D90F5")
                    for option in hash_options:
                        listbox.insert(tk.END, option)
                    listbox.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)

                    tk.Button(top, text="Selectează", command=set_choice,
                            font=("yu gothic ui bold", 11), bg="#1D90F5", fg="white").pack(pady=10)

                    listbox.bind("<Double-Button-1>", lambda event: set_choice())
            except Exception as e:
                messagebox.showerror("Eroare", str(e))

        threading.Thread(target=run_detect, daemon=True).start()

    
    def update_ui_for_mode(self, *args):
        mode = self.attack_mode.get()
        if mode == "wordlist":
            self.charset_entry.config(state="disabled")
            self.maxlen_entry.config(state="disabled")
            for rb in self.ram_radiobuttons:
                rb.config(state="normal")
        else:  # bruteforce
            self.charset_entry.config(state="normal")
            self.maxlen_entry.config(state="normal")
            for rb in self.ram_radiobuttons:
                rb.config(state="disabled")

    
    def start_attack(self):
        hash_value = self.hash_entry.get()
        mode = self.attack_mode.get()
        hash_type = self.hash_type.get().lower()
        charset = self.charset_entry.get()
        maxlen = self.maxlen_entry.get()
        threads = self.threads_entry.get().strip()
        original_wordlist = self.wordlist_path.get()

        if not original_wordlist or not os.path.exists(original_wordlist):
            messagebox.showerror("Eroare", "Selectează un fișier wordlist valid.")
            return

        # ✅ validare threads
        if not threads.isdigit() or int(threads) <= 0:
            messagebox.showerror("Eroare", "Introduceți un număr valid de threaduri (> 0).")
            return

        os.makedirs("wordlists", exist_ok=True)
        original_filename = os.path.basename(original_wordlist)
        persistent_path = os.path.join("wordlists", original_filename)

        if os.path.abspath(original_wordlist) != os.path.abspath(persistent_path):
            shutil.copyfile(original_wordlist, persistent_path)

        args = [
            os.path.join(os.path.dirname(__file__), "bruteforce_cli.exe"),
            "--hash", hash_value,
            "--type", hash_type,
            "--mode", mode,
            "--threads", threads
        ]

        if mode == "wordlist":
            args.extend(["--file", persistent_path])
            if self.ram_mode.get():
                args.extend(["--ram"])
        elif mode == "bruteforce":
            args.extend(["--charset", charset, "--max-len", maxlen])

        def run_golang():
            try:
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"[DEBUG {timestamp}] Comandă trimisă către Go:")
                print(" ".join(args))
                result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace')
                output = result.stdout if result.returncode == 0 else result.stderr
                messagebox.showinfo("Rezultat", output)
            except Exception as e:
                messagebox.showerror("Eroare", str(e))

        threading.Thread(target=run_golang, daemon=True).start()


    def show(self):
        self.frame.place(x=0, y=180, width=1060, height=560)

    def hide(self):
        self.frame.place_forget()