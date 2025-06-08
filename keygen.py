from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open("private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open("public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("[+] Yeni RSA key pair oluşturuldu.")

if __name__ == "__main__":
    priv_exists = os.path.exists("private.pem")
    pub_exists = os.path.exists("public.pem")

    if priv_exists and pub_exists:
        os.remove("private.pem")
        os.remove("public.pem")
        print("[!] Mevcut RSA anahtarları silindi. Yeni anahtarlar oluşturuluyor...")
        generate_keys()
    elif priv_exists or pub_exists:
        print("[!] Anahtarlardan biri eksikti. Mevcut dosya da silinip yeni anahtarlar oluşturuluyor...")
        if priv_exists:
            os.remove("private.pem")
        if pub_exists:
            os.remove("public.pem")
        generate_keys()
    else:
        print("[i] RSA anahtarları bulunamadı. İlk defa oluşturuluyor...")
        generate_keys()
