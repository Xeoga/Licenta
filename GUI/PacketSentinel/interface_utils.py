import wmi
import re
from scapy.all import get_if_list, get_if_hwaddr

def normalize_mac(mac):
    return re.sub(r'[^a-f0-9]', '', mac.lower())

def get_windows_interfaces():
    c = wmi.WMI()
    interfete = []
    for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        if nic.MACAddress and nic.IPAddress:
            interfete.append({
                "description": nic.Description,
                "ip": nic.IPAddress[0],
                "mac": normalize_mac(nic.MACAddress)
            })
    return interfete

def get_scapy_interfaces():
    interfete = []
    for iface in get_if_list():
        try:
            mac = get_if_hwaddr(iface)
            interfete.append({
                "scapy_name": iface,
                "mac": normalize_mac(mac)
            })
        except Exception:
            continue
    return interfete

def coreleaza_interfete():
    win_ifs = get_windows_interfaces()
    scapy_ifs = get_scapy_interfaces()
    corelate = []
    for win_iface in win_ifs:
        for scapy_iface in scapy_ifs:
            if win_iface["mac"] == scapy_iface["mac"]:
                corelate.append({
                    "description": win_iface["description"],
                    "ip": win_iface["ip"],
                    "scapy_name": scapy_iface["scapy_name"]
                })
    return corelate
