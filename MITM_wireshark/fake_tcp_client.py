import socket

HOST = "127.0.0.1"  # kendi receiver IP’n ile değiştir (saldırının hedef IP adresi)
PORT = 9000         # receiver.py zaten bu portta dinliyor (hedef port)

try:
    # TCP soketi oluşturuluyor (AF_INET: IPv4, SOCK_STREAM: TCP)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Belirtilen IP ve port'a TCP bağlantısı kuruluyor
    s.connect((HOST, PORT))

    # Sahte bir veri paketi gönderiliyor (örnek olarak saldırı simülasyonu)
    s.sendall(b"FAKE_PACKET_FROM_ATTACKER")

    # Bağlantı kapatılıyor
    s.close()

    # Başarılı bağlantı ve veri gönderimi mesajı
    print("[✓] Sahte TCP bağlantısı kuruldu ve veri gönderildi.")
except Exception as e:
    # Hata durumunda açıklayıcı mesaj basılır
    print(f"[!] Bağlantı başarısız: {e}")
