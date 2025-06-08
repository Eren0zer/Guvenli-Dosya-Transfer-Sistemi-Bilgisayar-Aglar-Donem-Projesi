import socket
from scapy.all import get_if_list, get_if_addr

# Aktif IP'yi bul
# Bilgisayarın ağ adını (hostname) alıyoruz
hostname = socket.gethostname()

# Hostname'e ait yerel IP adresi alınır (genellikle 127.0.0.1 dışında bir IP)
local_ip = socket.gethostbyname(hostname)
print(f"[i] Yerel IP adresin: {local_ip}")

# IP ile eşleşen arayüzü bul
# Tüm ağ arayüzlerini döngüyle kontrol ederek bu IP'ye sahip olanı bulmaya çalışıyoruz
for iface in get_if_list():
    try:
        # Arayüzün IP adresi alınır
        ip = get_if_addr(iface)
        # Eğer bu IP, yerel IP ile eşleşiyorsa, bu aktif ağ arayüzü olabilir
        if ip == local_ip:
            print(f"[✅] Bu senin aktif arayüzün olabilir: {iface}")
    except Exception:
        # Herhangi bir hata (örneğin IP atanamamış arayüzler) göz ardı edilir
        pass
