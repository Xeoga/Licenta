### main.py ###
from gui import TrafficAnalyzerGUI
import tkinter as tk

def main():
    root = tk.Tk()
    app = TrafficAnalyzerGUI(root)
    root.resizable(False, False)
    root.mainloop()

if __name__ == "__main__":
    main()
