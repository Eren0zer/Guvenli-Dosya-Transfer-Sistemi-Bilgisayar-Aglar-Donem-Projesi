import socket
import hashlib
import os
import sys
import datetime
import json
import time
import subprocess

# 🔐 Şifreleme için eklenen kütüphaneler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from collections import defaultdict


FRAGMENT_SIZE = 1024
HASH_SIZE = 32
HEADER_SIZE = 4
PACKET_SIZE = FRAGMENT_SIZE + HASH_SIZE + HEADER_SIZE
SHARED_SECRET = "sifre123"
PRIVATE_KEY_FILE = "private.pem"


failed_attempts = defaultdict(int)
blocked_ips = set()
BLOCK_LIMIT = 3
BLOCKED_IP_FILE = "blocked_ips.txt"
FAILED_ATTEMPTS_FILE = "failed_ips.json"

ip_chunk_counter = defaultdict(int)
ip_first_time = {}
FLOOD_LIMIT = 20  # aynı IP'den gelen max chunk sayısı (örnek)


def load_blocked_ips():
    if os.path.exists(BLOCKED_IP_FILE):
        with open(BLOCKED_IP_FILE, "r") as f:
            return set(f.read().splitlines())
    return set()

def save_blocked_ip(ip):
    with open(BLOCKED_IP_FILE, "a") as f:
        f.write(f"{ip}\n")

def load_failed_attempts():
    if not os.path.exists("failed_ips.json"):
        return {}

    with open("failed_ips.json", "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}  # Eğer dosya boşsa varsayılan olarak boş sözlük döndür


def save_failed_attempts(data):
    with open(FAILED_ATTEMPTS_FILE, "w") as f:
        json.dump(data, f)


def get_rtt(ip):
    #return 150
    try:
        result = subprocess.run(["ping", "-n", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.split("\n"):
            if "Average" in line or "Ort" in line:
                return int(line.split("=")[-1].replace("ms", "").strip())
    except:
        pass
    return 999


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            if data == b"":
                return None
            else:
                break
        data += chunk
    return data


def log_message(msg, log_file="log.txt"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def print_progress(current, total):
    bar_len = 40
    filled = int(bar_len * current / total)
    bar = "=" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\rProgress: [{bar}] {current}/{total}\n")
    sys.stdout.flush()

def receive_file_udp(ip='0.0.0.0', port=9000):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"[UDP] Dinleniyor: {ip}:{port}")

    data_chunks = {}
    filename = None
    total_chunks = None

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            ip, port = addr
            now = time.time()

            if ip not in ip_first_time:
                ip_first_time[ip] = now

            ip_chunk_counter[ip] += 1

            duration = now - ip_first_time[ip]
            if ip_chunk_counter[ip] >= FLOOD_LIMIT and duration < 10:
                log_message(f"[THREAT] UDP flood şüphesi: {ip} → {ip_chunk_counter[ip]} chunk / {duration:.2f}s")
                print(f"[⚠️] UDP flood şüphesi: {ip}")
                print(f"[❌] {ip} flood şüphesi nedeniyle paket işlenmedi ve receiver kapatılıyor.")
                exit()
                

            # SAHTE PAKET (too short) tespiti
            if len(data) < 12:
                log_message(f"[THREAT] Geçersiz UDP paketi: {ip} → Yetersiz veri ({len(data)} bayt)")
                print(f"[❗] Geçersiz UDP paketi tespit edildi → {ip}")
                exit()

            if not data:
                continue

            name_len = int.from_bytes(data[:4], 'big')
            filename = data[4:4+name_len].decode()
            chunk_id = int.from_bytes(data[4+name_len:8+name_len], 'big')
            total_chunks = int.from_bytes(data[8+name_len:12+name_len], 'big')
            chunk = data[12+name_len:]

            data_chunks[chunk_id] = chunk

            print(f"[UDP] Chunk {chunk_id+1}/{total_chunks} alındı.")
            log_message(f"[UDP] Chunk {chunk_id+1}/{total_chunks} alındı.")

            if len(data_chunks) == total_chunks:
                break

        except Exception as e:
            print("[!] UDP alma hatası:", e)
            log_message(f"[ERROR] UDP alma hatası: {e}")
            break

    sock.close()

    if filename:
        # UDP dosya ismi otomatikleştir
        base_name = f"received_udp_{filename}"
        counter = 1
        while os.path.exists(f"received_udp_{counter}_{filename}"):
            counter += 1
        save_path = f"received_udp_{counter}_{filename}"

        with open(save_path, 'wb') as f:
            for i in sorted(data_chunks.keys()):
                f.write(data_chunks[i])

        print(f"[UDP] Dosya kaydedildi: {save_path}")
        log_message(f"[UDP] Dosya kaydedildi: {save_path}")
        log_message(f"[SUMMARY] Alınan dosya: {filename}, Toplam chunk: {total_chunks}")


def start_server(ip='127.0.0.1', port=9000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((ip, port))
        server.listen()
        print(f"[+] Listening on {ip}:{port}")
        conn, addr = server.accept()
        handle_tcp_connection(conn, addr)

def handle_tcp_connection(conn, addr):
    with conn:
        print(f"[+] Connected by {addr}")
        client_ip = addr[0]

        # ⬇️ Dosyadan IP bilgilerini yükle
        blocked_ips = load_blocked_ips()
        failed_attempts = load_failed_attempts()

        if client_ip in blocked_ips:
            print(f"[BLOCKED] Bağlantı reddedildi – engellenmiş IP: {client_ip}")
            log_message(f"[BLOCKED] Bağlantı reddedildi – engellenmiş IP: {client_ip}")
            conn.close()
            return

        auth_len_bytes = conn.recv(4)
        if not auth_len_bytes:
            print("[!] Bağlantı erken kapandı (auth len)")
            return

        auth_len = int.from_bytes(auth_len_bytes, byteorder='big')
        auth_data = conn.recv(auth_len).decode()

        if auth_data != SHARED_SECRET:
            count = failed_attempts.get(client_ip, 0) + 1
            failed_attempts[client_ip] = count
            save_failed_attempts(failed_attempts)

            log_message(f"[AUTH_FAIL] {client_ip} → Şifre hatalı ({count})")
            print(f"[❌] Şifre hatalı! ({count}) → {client_ip}")

            if count >= BLOCK_LIMIT:
                save_blocked_ip(client_ip)
                log_message(f"[BLOCKED] {client_ip} kalıcı olarak engellendi – {BLOCK_LIMIT} hatalı giriş")
                print(f"[🚫] {client_ip} kalıcı olarak engellendi")

            conn.close()
            return
        
        else:
            print("[✅] Authentication successful.")
            log_message(f"[AUTH] Authentication successful from {addr}")



        encrypted_key_len = int.from_bytes(recv_exact(conn, 4), byteorder='big')
        encrypted_key = recv_exact(conn, encrypted_key_len)
        iv = recv_exact(conn, 16)

        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        log_message("[KEY] AES anahtarı RSA ile başarıyla çözüldü.")

        name_len_bytes = recv_exact(conn, 4)
        if not name_len_bytes:
            print("[!] Failed to receive filename length.")
            return
        name_len = int(name_len_bytes.decode())

        filename_bytes = recv_exact(conn, name_len)
        if not filename_bytes:
            print("[!] Failed to receive filename.")
            return
        filename = filename_bytes.decode()

        total_fragments_bytes = recv_exact(conn, 4)
        if not total_fragments_bytes:
            print("[!] Failed to receive total fragment count.")
            return
        total_fragments = int.from_bytes(total_fragments_bytes, byteorder='big')
        print(f"[+] Expecting {total_fragments} fragments.")
        log_message(f"[INFO] Expecting {total_fragments} fragments for file: {filename}")

        save_path = f"received_{filename}"
        i = 1
        while os.path.exists(save_path):
            save_path = f"received_{i}_{filename}"
            i += 1

        fragments = {}
        bad_fragments = []

        while True:
            packet = recv_exact(conn, PACKET_SIZE)
            if not packet:
                print(f"[!] No more packets received. Last known fragment: {max(fragments.keys(), default='N/A')}")
                break

            if len(packet) < HEADER_SIZE + HASH_SIZE:
                print("[!] Incomplete packet, skipping.")
                continue

            fragment_id = int.from_bytes(packet[:HEADER_SIZE], byteorder='big')
            encrypted_data = packet[HEADER_SIZE:-HASH_SIZE]
            received_hash = packet[-HASH_SIZE:]
            computed_hash = hashlib.sha256(encrypted_data).digest()

            print(f"[DEBUG] Fragment ID: {fragment_id}")
            if received_hash != computed_hash:
                print(f"[!] Fragment {fragment_id} corrupted! Skipped.")
                log_message(f"[FRAGMENT] Fragment {fragment_id} failed hash verification. Skipped.")
                print(f"[DEBUG] Hash mismatch detected!")
                print(f"[DEBUG] Expected: {received_hash.hex()}")
                print(f"[DEBUG] Actual:   {computed_hash.hex()}")
                bad_fragments.append(fragment_id)
                continue

            try:
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                fragments[fragment_id] = decrypted_data
                print_progress(len(fragments), total_fragments)
                log_message(f"[FRAGMENT] Fragment {fragment_id} received and decrypted successfully.")

            except Exception as e:
                print(f"[!] Decryption failed for fragment {fragment_id}: {e}")
                log_message(f"[FRAGMENT] Fragment {fragment_id} decryption failed: {e}")
                bad_fragments.append(fragment_id)
                continue

        received_ids = set(fragments.keys())
        expected_ids = set(range(total_fragments))
        missing_fragments = sorted(expected_ids - received_ids)

        if missing_fragments:
            print(f"\n[!] Missing fragments: {missing_fragments}")

        with open(save_path, "wb") as f:
            for i in sorted(fragments.keys()):
                f.write(fragments[i])



        print("\n[+] File reconstructed and saved as", save_path)
        log_message(f"[SUCCESS] File saved as {save_path}, received {len(received_ids)}/{total_fragments} fragments.")
        print(f"\n[i] Total fragments received: {len(received_ids)}")
        print(f"[i] Fragment IDs received: {sorted(received_ids)}")
        print(f"[i] Fragment IDs missing: {missing_fragments}")

        log_message(f"[RECEIVED] Dosya: {save_path}, Alınan Parçalar: {len(fragments)}/{total_fragments}")
        if bad_fragments:
            log_message(f"[WARN] Bozuk Parçalar Atlandı: {bad_fragments}")
        if missing_fragments:
            log_message(f"[WARN] Eksik Parçalar: {missing_fragments}")


if __name__ == "__main__":
    ip = '127.0.0.1'
    rtt = get_rtt(ip)
    print(f"[RTT] {rtt}ms ölçüldü.")
    if rtt > 100:
        print("[ADAPT] RTT yüksek, UDP moduna geçiliyor.")
        receive_file_udp('0.0.0.0')
    else:
        print("[ADAPT] RTT düşük, TCP modunda dinleniyor.")
        start_server(ip)


