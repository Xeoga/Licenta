import wmi
import re
from scapy.all import get_if_list, get_if_hwaddr, sniff

def normalize_mac(mac):
    """Normalizează MAC-ul pentru comparare (fără delimitatori, litere mici)."""
    return re.sub(r'[^a-f0-9]', '', mac.lower())

def get_windows_interfaces():
    """Returnează interfețele active cu IP și MAC din WMI."""
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
    """Returnează interfețele din Scapy și adresele lor MAC."""
    interfete = []
    for iface in get_if_list():
        try:
            mac = get_if_hwaddr(iface)
            interfete.append({
                "scapy_name": iface,
                "mac": normalize_mac(mac)
            })
        except Exception:
            continue  # unele interfețe pot da eroare
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

def sniff_pe_corelata():
    corelate = coreleaza_interfete()
    
    print("🔎 Interfețe corelate:")
    for i, iface in enumerate(corelate):
        print(f"[{i}] {iface['description']} → {iface['ip']} → {iface['scapy_name']}")
    
    if not corelate:
        print("⚠️ Nu s-au găsit interfețe corelate.")
        return

    idx = int(input("\nAlege indexul interfeței pentru captură: "))
    scapy_name = corelate[idx]["scapy_name"]

    print(f"\n📡 Capturare pe: {scapy_name}")
    packets = sniff(iface=scapy_name, count=10)
    packets.summary()

if __name__ == "__main__":
    sniff_pe_corelata()
