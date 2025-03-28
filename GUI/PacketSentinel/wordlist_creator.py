import tkinter as tk
import os

def launch_wordlist_creator():
    top = tk.Toplevel()
    top.title("Creare Wordlist")
    top.geometry("420x500+500+200")
    top.configure(bg="#1E1E1E")
    top.grab_set()

    entries_frame = tk.Frame(top, bg="#1E1E1E")
    entries_frame.pack(pady=10, fill=tk.BOTH, expand=True)

    entry_rows = []

    def update_buttons():
        for i, row in enumerate(entry_rows):
            plus_btn = row["plus"]
            minus_btn = row["minus"]

            # Activează "+" doar pentru ultimul rând
            if i == len(entry_rows) - 1:
                plus_btn.config(state="normal", bg="#3D404B", fg="white")
            else:
                plus_btn.config(state="disabled", bg="#2E2E2E", fg="#777777")

            # Dezactivează "-" doar pentru ultimul rând
            if len(entry_rows) == 1 or i == len(entry_rows) - 1:
                minus_btn.config(state="disabled", bg="#2E2E2E", fg="#777777")
            else:
                minus_btn.config(state="normal", bg="#3D404B", fg="white")

    def remove_row(row_frame):
        for r in entry_rows:
            if r["frame"] == row_frame:
                r["frame"].destroy()
                entry_rows.remove(r)
                break
        update_buttons()

    def add_row():
        row_frame = tk.Frame(entries_frame, bg="#1E1E1E")
        row_frame.pack(fill=tk.X, pady=2, padx=10)

        entry = tk.Entry(row_frame, font=("yu gothic ui", 11),
                        bg="#1A1A1A", fg="#DDDDDD", insertbackground="white",
                        relief="flat", highlightthickness=0, disabledbackground="#1A1A1A", disabledforeground="#666666")

        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def on_add():
            if entry.get().strip():
                entry.config(state="readonly", readonlybackground="#1A1A1A", disabledforeground="white")
                add_row()
            update_buttons()

        def on_remove():
            remove_row(row_frame)

        minus_btn = tk.Button(row_frame, text="-", command=on_remove,
                              bg="#3D404B", fg="white", activebackground="#5A5A5A",
                              relief="flat", width=2, cursor="hand2")
        minus_btn.pack(side=tk.RIGHT, padx=(5, 0))

        plus_btn = tk.Button(row_frame, text="+", command=on_add,
                             bg="#3D404B", fg="white", activebackground="#5A5A5A",
                             relief="flat", width=2, cursor="hand2")
        plus_btn.pack(side=tk.RIGHT)

        entry_rows.append({"entry": entry, "frame": row_frame, "plus": plus_btn, "minus": minus_btn})
        update_buttons()
        entry.focus_set()

    add_row()

    # Nume fișier
    tk.Label(top, text="Nume fișier:", bg="#1E1E1E", fg="white", font=("yu gothic ui", 12)).pack(pady=(10, 0))
    filename_entry = tk.Entry(top, font=("yu gothic ui", 12), bg="white", relief="flat", justify="center")
    filename_entry.insert(0, "wordlist_custom.txt")
    filename_entry.pack(pady=5)

    def save_wordlist():
        filename = filename_entry.get().strip()
        if not filename:
            return

        os.makedirs("wordlists", exist_ok=True)
        filepath = os.path.join("wordlists", filename)

        with open(filepath, "w", encoding="utf-8") as f:
            for row in entry_rows:
                val = row["entry"].get().strip()
                if val:
                    f.write(val + "\n")

        top.destroy()

    save_btn = tk.Button(top, text="Salvează Wordlist", command=save_wordlist,
                         font=("yu gothic ui bold", 11), bg="#1D90F5", fg="white", activebackground="#5A5A5A",
                         relief="flat", cursor="hand2")
    save_btn.pack(pady=20)
