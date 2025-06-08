# "example.txt" ve "received_example.txt" dosyaları ikili (binary) modda okunmak üzere açılıyor
with open("example.txt", "rb") as f1, open("received_example.txt", "rb") as f2:
    # Her iki dosya da tamamen okunup içerikleri karşılaştırılıyor
    if f1.read() == f2.read():
        # İçerikler aynıysa doğrulama başarılı mesajı yazdırılıyor
        print("✅ Dosyalar tamamen aynı!")
    else:
        # İçerikler farklıysa hata mesajı yazdırılıyor
        print("❌ Dosyalar farklı!")
