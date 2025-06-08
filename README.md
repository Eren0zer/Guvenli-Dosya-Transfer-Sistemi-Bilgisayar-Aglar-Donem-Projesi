#  Güvenli Dosya Transfer Sistemi – Bilgisayar Ağları Dönem Projesi

##  Proje Özeti

Bu proje, dosya transferi sürecinde veri güvenliği, bütünlüğü ve düşük seviyeli IP başlık işleme gibi ağ programlamanın temel konularını kapsayan kapsamlı bir uygulamadır. AES-256 ile şifreleme, RSA-2048 ile anahtar güvenliği, SHA-256 ile bütünlük doğrulama, IP header manipülasyonu ve saldırı simülasyonları gibi ileri düzey özellikler sunar.


---

## 🔐 Güvenlik Mekanizmaları

- ✅ **AES-256** ile her dosya parçası ayrı ayrı şifrelenir.
- ✅ **RSA-2048** ile AES anahtarı güvenle iletilir.
- ✅ **SHA-256** hash fonksiyonu ile veri bütünlüğü sağlanır.
- ✅ Kimlik doğrulama (Shared Secret) yapılır.
- ✅ IP bazlı erişim kontrolü ve hatalı giriş engellemesi mevcuttur.

---

## 🧬 Düşük Seviyeli IP Başlık İşleme

- 📌 TTL, DF bayrağı, Fragment Offset ve Checksum değerleri `Scapy` kullanılarak manuel olarak ayarlanır.
- 📥 Paketler Wireshark ve `tshark` üzerinden analiz edilir.
- 📌 Header checksum fonksiyonu projeye entegre edilmiştir.

---

## ⚔️ Saldırı Simülasyonları

- 🧨 **UDP Flood** saldırısı (`fake_udp_flood.py`)
- 🧪 **Geçersiz UDP Paket** enjeksiyonu (`fake_udp_invalid_packet.py`)
- 🧠 Flood algılama ve paket işleme sınırlandırması
- ⛔ Geçersiz veri alanı olan UDP paketlerini reddetme ve programı kapatma

---

## 📶 Ağ Performans Ölçümü

- 🔁 RTT/Ping ölçümü (`ping_test`)
- 🚀 Bant genişliği analizi (`iperf3_test`)
- 📉 Paket kaybı ve gecikme simülasyonu (`network.sh`)
- 📋 Farklı bağlantı koşulları testleri (loopback, Wi-Fi vb.)

---

## 📝 Log Kayıt Sistemi

- `log.txt` içerisine zaman damgalı tüm olaylar kaydedilir.
  - [CONNECT], [AUTH], [KEY], [INFO], [FRAGMENT], [SUCCESS], [WARN], [THREAT] türleriyle sınıflandırılır.
- `transfer_log.txt` dosyasına ise sadece transfer özetleri (fragment sayısı, eksikler vb.) yazılır.
- Örnek bir log çıktısı:

---

## 🧪 Kullanım

### Gereksinimler

- Python 3.8+
- Kütüphaneler:
  - `cryptography`
  - `scapy`
  - `platform`, `subprocess`, `socket`, `datetime`
- `iperf3`, `tc`, `Wireshark`

### Kurulum

```bash
pip install cryptography scapy
pip install pycryptodome
pip install colorama
pip install npcap
```

### Başlatma
```bash
python keygen.py      # Anahtar çiftini üretir
python receiver.py    # Alıcıyı başlatır
python sender.py      # Dosya gönderimini başlatır
```

### Performans Testi Başlatma
```bash
python keygen.py      
python performance_test.py
python sender.py     
```
---

## 📁 Klasör Yapısı












