import PySimpleGUI as sg

def on_button_click(action):
    print(f"{action} clicked")

# Define layout with styling to match the interface
sg.theme("DarkGrey5")  # Set theme for a similar look

button_style = {"size": (12, 1), "pad": (2, 2), "button_color": ("black", "#f5f5f5")}
header_style = {"size": (15, 1), "font": ("Arial", 10, "bold"), "pad": (2, 2), "button_color": ("black", "#d9d9d9")}

layout = [
    [sg.Button("Dashboard", **header_style), sg.Button("Target", **header_style), sg.Button("Proxy", **header_style),
     sg.Button("Intruder", **header_style), sg.Button("Repeater", **header_style), sg.Button("Sequencer", **header_style),
     sg.Button("Decoder", **header_style), sg.Button("Comparer", **header_style), sg.Button("Extender", **header_style),
     sg.Button("Project options", **header_style), sg.Button("User options", **header_style)],
    [sg.Button("New Scan", **button_style), sg.Button("New Live Task", **button_style), sg.Text("Issue Activity", font=("Arial", 10, "bold"))]
]

# Create window
window = sg.Window("Custom Security Interface", layout, size=(900, 200), element_justification='left')

# Event loop
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break
    on_button_click(event)

window.close()
