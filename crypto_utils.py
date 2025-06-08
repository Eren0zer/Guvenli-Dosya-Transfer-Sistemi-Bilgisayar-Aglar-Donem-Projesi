from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AES için rastgele anahtar üret
def generate_aes_key(length=32):
    return os.urandom(length)  # 32 byte = 256-bit

# AES ile şifreleme (CBC)
def encrypt_aes(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding: 16 byte hizalama
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len] * pad_len)

    ct = encryptor.update(data) + encryptor.finalize()
    return iv + ct  # IV + ciphertext

# AES ile çözme
def decrypt_aes(key, encrypted_data):
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ct) + decryptor.finalize()

    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# AES anahtarını RSA public key ile şifrele
def encrypt_rsa(public_key_path, data):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted

# RSA private key ile AES anahtarını çöz
def decrypt_rsa(private_key_path, encrypted_data):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted
