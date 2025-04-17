### main.py ###
from gui import TrafficAnalyzerGUI
import tkinter as tk
from load_user_session import load_user_session

def main():
    user_data = load_user_session()
    username = user_data["first_name"] if user_data else "Guest"
    print(username)
    root = tk.Tk()
    app = TrafficAnalyzerGUI(root, username=username)  # înlocuiește cu username-ul real)
    root.resizable(False, False)
    root.mainloop()

if __name__ == "__main__":
    main()