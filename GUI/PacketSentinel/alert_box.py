import tkinter as tk
from datetime import datetime
import json
import os
import re

class AlertBox:
    ALERT_TYPES = {
        "INFO": {"prefix": "ℹ️", "color": "white"},
        "WARN": {"prefix": "⚠️", "color": "#FFD600"},
        "CRITICAL": {"prefix": "🚨", "color": "#FF1744"}
    }

    def __init__(self, parent, x=980, y=110, width=530, height=633):
        self.frame = tk.Frame(parent, bg="#3A3D4A", bd=2, relief="ridge")
        self.frame.place(x=x, y=y, width=width, height=height)

        self.today = datetime.now().strftime("%Y-%m-%d")
        os.makedirs("log", exist_ok=True)
        self.alert_log_path = f"log/alerts_{self.today}.log"
        self.alert_json_path = f"log/alerts_{self.today}.json"
        self.alert_stats = {}

        title_frame = tk.Frame(self.frame, bg="#3A3D4A")
        title_frame.pack(fill=tk.X, pady=5)

        title = tk.Label(title_frame, text="🛡️ Alerte de securitate", font=("yu gothic ui bold", 14), bg="#3A3D4A", fg="white")
        title.pack(side=tk.LEFT, padx=10)

        clear_btn = tk.Button(title_frame, text="🗑️ Șterge", command=self.clear_alerts,
                              font=("yu gothic ui", 10), bg="#D32F2F", fg="white", relief="flat", cursor="hand2")
        clear_btn.pack(side=tk.RIGHT, padx=10)

        self.text = tk.Text(
            self.frame, bg="#1E1E1E", fg="white",
            font=("Consolas", 10), wrap="word", relief="flat",
            height=32, width=50
        )
        self.text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        if not os.path.exists(self.alert_json_path):
            with open(self.alert_json_path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def add_alert(self, message: str, level="INFO"):
        level = level.upper()
        alert_type = self.ALERT_TYPES.get(level, self.ALERT_TYPES["INFO"])
        prefix = alert_type["prefix"]
        color = alert_type["color"]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] {prefix} {message}\n"

        # Afișare în interfață
        self.text.insert(tk.END, formatted)
        self.text.tag_add(level, f"end-{len(formatted)}c", "end-1c")
        self.text.tag_config(level, foreground=color)
        self.text.see(tk.END)

        # Salvare în fișier .log
        with open(self.alert_log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {level}: {message}\n")

        # Salvare în fișier .json
        alert_obj = {"timestamp": timestamp, "level": level, "message": message}
        with open(self.alert_json_path, "r+", encoding="utf-8") as f:
            try:
                alerts = json.load(f)
            except json.JSONDecodeError:
                alerts = []
            alerts.append(alert_obj)
            f.seek(0)
            json.dump(alerts, f, indent=2)

        # Actualizare statistici per IP
        ip = self.extract_ip(message)
        if ip:
            self.alert_stats.setdefault(ip, {"INFO": 0, "WARN": 0, "CRITICAL": 0})
            self.alert_stats[ip][level] += 1

    def clear_alerts(self):
        self.text.delete(1.0, tk.END)

    def extract_ip(self, text: str):
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
        return match.group(1) if match else None

    def get_alert_stats(self):
        return self.alert_stats
