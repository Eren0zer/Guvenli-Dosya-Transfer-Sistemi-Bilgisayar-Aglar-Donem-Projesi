from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AES için rastgele bir anahtar üreten fonksiyon
# Varsayılan olarak 32 byte (256 bit) uzunluğunda anahtar üretir
def generate_aes_key(length=32):
    return os.urandom(length)  # 32 byte = 256-bit

# AES algoritması kullanarak CBC modunda veri şifreleyen fonksiyon
def encrypt_aes(key, data):
    # 16 byte’lık rastgele bir IV (Initialization Vector) üretiliyor
    iv = os.urandom(16)
    
    # AES CBC modu için Cipher nesnesi oluşturuluyor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding işlemi: Blok uzunluğunun katı olacak şekilde veri uzatılıyor (PKCS7 benzeri)
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len] * pad_len)

    # Veriyi şifrele (update + finalize)
    ct = encryptor.update(data) + encryptor.finalize()

    # IV başa eklenerek şifreli veri döndürülüyor (IV + ciphertext)
    return iv + ct

# AES ile şifrelenmiş veriyi çözen fonksiyon
def decrypt_aes(key, encrypted_data):
    # İlk 16 byte IV, geri kalanı şifreli veri (ciphertext)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]

    # AES CBC çözümleyici oluşturuluyor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Şifreli veri çözülüyor
    decrypted = decryptor.update(ct) + decryptor.finalize()

    # Padding uzunluğu sondaki bayttan alınır ve çıkarılır
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# Verilen RSA public key ile AES anahtarını şifreleyen fonksiyon
def encrypt_rsa(public_key_path, data):
    # Public key dosyasından okunur ve PEM formatında yüklenir
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # OAEP padding ile RSA şifreleme yapılır (SHA-256 kullanılır)
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted

# RSA private key kullanarak şifrelenmiş AES anahtarını çözen fonksiyon
def decrypt_rsa(private_key_path, encrypted_data):
    # Private key dosyasından okunur ve PEM formatında yüklenir
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # OAEP padding ile RSA çözümleme yapılır
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted
