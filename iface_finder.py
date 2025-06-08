import socket
from scapy.all import get_if_list, get_if_addr

# Aktif IP'yi bul
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
print(f"[i] Yerel IP adresin: {local_ip}")

# IP ile eşleşen arayüzü bul
for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        if ip == local_ip:
            print(f"[✅] Bu senin aktif arayüzün olabilir: {iface}")
    except Exception:
        pass
