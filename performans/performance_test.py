import subprocess
import platform
import datetime
import os

# Hedef IP adresine ping atıp sonucu döndüren fonksiyon
def ping_test(target_ip):
    print(f"[•] {target_ip} adresine ping atılıyor...")
    
    # Windows ise "-n", diğer sistemlerde "-c" parametresi kullanılır
    count = "4"
    param = "-n" if platform.system().lower() == "windows" else "-c"
    
    try:
        # Ping komutu subprocess ile çalıştırılır ve çıktısı alınır
        output = subprocess.check_output(["ping", param, count, target_ip], universal_newlines=True)
        return output
    except Exception as e:
        # Ping başarısız olursa hata mesajı döndürülür
        return f"[!] Ping başarısız: {e}"

# iPerf3 ile bant genişliği testini gerçekleştiren fonksiyon
def iperf_test(target_ip, port="5201"):
    print(f"[•] {target_ip}:{port} adresinde iperf3 testi başlatılıyor...")
    try:
        # iPerf3 istemci olarak hedefe 5 saniyelik test yapar
        output = subprocess.check_output(
            ["iperf3", "-c", target_ip, "-p", port, "-t", "5"],
            universal_newlines=True
        )
        return output
    except Exception as e:
        # Test başarısız olursa hata mesajı döndürülür
        return f"[!] iPerf3 testi başarısız: {e}"

# Zaman damgalı bir dosya ismi üreten yardımcı fonksiyon
def create_timestamped_filename(prefix="performance_results", extension=".txt"):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{prefix}_{now}{extension}"

# Ana fonksiyon: kullanıcıdan IP alır, testleri yapar, sonuçları dosyaya yazar
def main():
    # Kullanıcıdan hedef IP adresi alınır
    ip = input("Test etmek istediğin hedef IP adresini gir: ").strip()
    port = "5201"  # Gerekirse port burada değiştirilebilir

    print("\n===== AĞ PERFORMANS TESTİ BAŞLATILIYOR =====\n")
    now = datetime.datetime.now()
    filename = create_timestamped_filename()
    
    # Sonuçlar liste halinde toplanır
    results = []
    results.append("╔════════════════════════════════════════════╗")
    results.append("║           AĞ PERFORMANS RAPORU            ║")
    results.append("╚════════════════════════════════════════════╝\n")
    results.append(f"🕒 Tarih: {now}")
    results.append(f"🎯 Test Hedefi: {ip}:{port}\n")
    
    results.append("═══════════════════════")
    results.append("🕒 PING TESTİ SONUCU:")
    results.append("═══════════════════════")
    results.append(ping_test(ip))  # Ping test sonucu eklenir

    results.append("\n═══════════════════════")
    results.append("🚀 IPERF3 BAND GENİŞLİĞİ:")
    results.append("═══════════════════════")
    results.append(iperf_test(ip, port=port))  # iPerf testi sonucu eklenir

    # Sonuçlar dosyaya yazılır
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(results))

    print(f"\n✅ Test tamamlandı. Ayrıntılı sonuçlar '{filename}' dosyasına yazıldı.")

# Script doğrudan çalıştırıldığında main() fonksiyonu devreye girer
if __name__ == "__main__":
    main()
