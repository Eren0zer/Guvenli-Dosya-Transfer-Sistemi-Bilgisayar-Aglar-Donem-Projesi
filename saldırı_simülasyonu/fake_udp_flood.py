# fake_udp_flood.py
import socket
import time

# Hedef IP ve port (receiver tarafı bu portta UDP dinliyor olmalı)
ip = '127.0.0.1'
port = 9000

# UDP soketi oluşturuluyor
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Normalden daha hızlı 50 sahte chunk gönderiyoruz (UDP flood simülasyonu)
for i in range(50):
    filename = b'fake.txt'           # Sahte dosya ismi
    chunk_id = i                     # Parça numarası
    total_chunks = 50                # Toplam parça sayısı
    
    # Paket başlığı: dosya ismi uzunluğu (4 byte) + dosya ismi + parça numarası (4 byte) + toplam parça sayısı (4 byte)
    header = (
        len(filename).to_bytes(4, 'big') +
        filename +
        chunk_id.to_bytes(4, 'big') +
        total_chunks.to_bytes(4, 'big')  # Bu alan eksikti, tamamlandı
    )

    # Her paketin gövdesi (payload) 500 byte'lık sahte veri içeriyor
    payload = b'A' * 500
    packet = header + payload  # Tam paket = başlık + içerik

    # UDP paketi gönderiliyor
    sock.sendto(packet, (ip, port))
    print(f"[>] {i+1}. sahte chunk gönderildi")

    # Her gönderim arasında 5 milisaniye bekleniyor (daha hızlı olmasını sağlamak için kısa tutulmuş)
    time.sleep(0.005)

# Soket kapatılıyor
sock.close()
