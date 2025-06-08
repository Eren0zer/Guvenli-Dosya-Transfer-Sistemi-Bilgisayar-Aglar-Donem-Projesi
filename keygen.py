# Gerekli kütüphaneler: RSA anahtarı üretimi ve PEM formatında yazmak için modüller
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# RSA anahtar çifti üretip dosyalara yazan fonksiyon
def generate_keys():
    # 2048 bitlik bir RSA özel anahtarı üretiliyor (public exponent olarak genellikle 65537 kullanılır)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Özel anahtardan public anahtar çıkarılıyor
    public_key = private_key.public_key()

    # Özel anahtar 'private.pem' dosyasına PEM formatında ve şifresiz olarak yazılıyor
    with open("private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Genel anahtar 'public.pem' dosyasına PEM formatında yazılıyor
    with open("public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("[+] Yeni RSA key pair oluşturuldu.")

# Kod doğrudan çalıştırıldığında aşağıdaki işlemler yapılır
if __name__ == "__main__":
    # Mevcut anahtar dosyalarının varlığı kontrol ediliyor
    priv_exists = os.path.exists("private.pem")
    pub_exists = os.path.exists("public.pem")

    if priv_exists and pub_exists:
        # Eğer her iki anahtar da varsa, silinip yeniden oluşturuluyor
        os.remove("private.pem")
        os.remove("public.pem")
        print("[!] Mevcut RSA anahtarları silindi. Yeni anahtarlar oluşturuluyor...")
        generate_keys()
    elif priv_exists or pub_exists:
        # Sadece biri varsa, o da silinip çift yeniden oluşturuluyor
        print("[!] Anahtarlardan biri eksikti. Mevcut dosya da silinip yeni anahtarlar oluşturuluyor...")
        if priv_exists:
            os.remove("private.pem")
        if pub_exists:
            os.remove("public.pem")
        generate_keys()
    else:
        # Hiç anahtar yoksa, ilk kez oluşturuluyor
        print("[i] RSA anahtarları bulunamadı. İlk defa oluşturuluyor...")
        generate_keys()
