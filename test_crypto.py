from crypto_utils import generate_aes_key, encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa

# 1. AES anahtarı üret
aes_key = generate_aes_key()
print("[1] AES Key:", aes_key.hex())

# 2. Veri hazırla
data = b"Bu bir test verisidir, sifrelenip cozulmelidir!"

# 3. AES ile şifrele
encrypted = encrypt_aes(aes_key, data)
print("[2] Encrypted with AES:", encrypted.hex())

# 4. AES ile çöz
decrypted = decrypt_aes(aes_key, encrypted)
print("[3] Decrypted:", decrypted.decode())

# 5. RSA ile AES anahtarını şifrele
rsa_encrypted_key = encrypt_rsa("public.pem", aes_key)
print("[4] AES key encrypted with RSA.")

# 6. RSA ile çöz
rsa_decrypted_key = decrypt_rsa("private.pem", rsa_encrypted_key)
print("[5] RSA decrypted AES key:", rsa_decrypted_key.hex())

# ✅ Son kontrol
assert aes_key == rsa_decrypted_key, "AES key RSA çözümünde uyuşmuyor!"
print("\n✅ Tüm şifreleme testleri başarıyla geçti.")
