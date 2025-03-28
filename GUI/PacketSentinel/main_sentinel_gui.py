import tkinter as tk
from hash_sentinel import HashSentinel
from packet_sentinel import PacketSentinel

class TrafficAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.configure(bg="#525561")

        width, height = 1300, 800
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 4) - (height // 4)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.attributes("-transparentcolor", "#525561")
        self.root.lift()
        self.root.focus_force()

        self.bg_frame = tk.Frame(self.root, bg="#272A37", bd=0)
        self.bg_frame.place(x=120, y=28, width=1060, height=740)

        # HEADER
        tk.Label(self.bg_frame, text="Sentinel", font=("yu gothic ui bold", 20), bg="#272A37", fg="white").place(x=30, y=30)
        self.mode_title = tk.Label(self.bg_frame, text="Traffic Analyzer", font=("yu gothic ui bold", 26), bg="#272A37", fg="white")
        self.mode_title.place(x=30, y=75)

        # TOP BUTTONS
        self.top_button_frame = tk.Frame(self.bg_frame, bg="#272A37")
        self.top_button_frame.place(x=30, y=130)

        self.packet_button = tk.Button(self.top_button_frame, text="PacketSentinel", font=("yu gothic ui", 12, "bold"),
                                       bg="#4A4A4A", fg="#FFFFFF", activebackground="#5A5A5A", activeforeground="#FFFFFF",
                                       relief=tk.FLAT, cursor="hand2", width=15, command=self.show_packet_frame)
        self.packet_button.pack(side=tk.LEFT, padx=5)

        self.hash_button = tk.Button(self.top_button_frame, text="HashSentinel", font=("yu gothic ui", 12, "bold"),
                                     bg="#4A4A4A", fg="#FFFFFF", activebackground="#5A5A5A", activeforeground="#FFFFFF",
                                     relief=tk.FLAT, cursor="hand2", width=15, command=self.show_hash_frame)
        self.hash_button.pack(side=tk.LEFT, padx=5)

        # ✅ Muta output_log aici sus!
        self.hash_sentinel = HashSentinel(self.bg_frame)
        self.packet_sentinel = PacketSentinel(self.bg_frame, self.output_log)

        # FOOTER
        tk.Label(self.bg_frame, text="Author: ~d0gma Team", font=("yu gothic ui", 12),
                 bg="#272A37", fg="#AAAAAA").place(x=800, y=710)

    def output_log(self, msg):
        print(msg)

    def show_packet_frame(self):
        self.hash_sentinel.hide()
        self.packet_sentinel.show()
        self.mode_title.config(text="Traffic Analyzer")

    def show_hash_frame(self):
        self.packet_sentinel.hide()
        self.hash_sentinel.show()
        self.mode_title.config(text="Hash Cracker")


def main():
    root = tk.Tk()
    app = TrafficAnalyzerGUI(root)
    root.resizable(False, False)
    root.mainloop()

if __name__ == "__main__":
    main()