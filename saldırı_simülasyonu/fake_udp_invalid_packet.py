# fake_udp_invalid_packet.py
import socket

# Hedef IP ve port bilgisi (UDP dinleyici bu adreste olmalı)
ip = '127.0.0.1'
port = 9000

# UDP soketi oluşturuluyor
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 🔴 Bilinçli olarak yalnızca 8 byte’lık veri gönderiliyor → Protokole uygun olmayan, eksik başlıklı paket
fake_data = b'\x00\x01\x02\x03\x04\x05\x06\x07'

# UDP paketi gönderiliyor (bu paketin yapısı eksik olduğu için receiver tarafından işlenemeyebilir)
sock.sendto(fake_data, (ip, port))

# Gönderim bildirimi
print("[!] Geçersiz (kısa) UDP paketi gönderildi.")

# Soket kapatılıyor
sock.close()
