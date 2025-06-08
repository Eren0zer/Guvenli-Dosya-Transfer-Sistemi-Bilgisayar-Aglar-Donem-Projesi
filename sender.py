import socket
import hashlib
import os
import sys
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, sendp, Ether, Raw, send
import random
import datetime
import subprocess
import time

FRAGMENT_SIZE = 1024
SKIP_FRAGMENTS = []
SHARED_SECRET = "sifre123"
PUBLIC_KEY_FILE = "public.pem"
SCAPY_IFACE = "\\Device\\NPF_{F6C392A5-D2DE-4A80-82A1-6EAFFFBAEDBD}"


def calculate_checksum(header_bytes):
    if len(header_bytes) % 2 != 0:
        header_bytes += b'\x00'
    total = 0
    for i in range(0, len(header_bytes), 2):
        word = (header_bytes[i] << 8) + header_bytes[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

def log_message(msg, log_file="log.txt"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def get_rtt(ip="127.0.0.1"):
    #return 150
    try:
        output = subprocess.check_output(["ping", "-n", "1", ip], universal_newlines=True)
        for line in output.splitlines():
            if "Average" in line:
                avg = int(line.split("Average = ")[-1].replace("ms", "").strip())
                return avg
    except Exception as e:
        log_message(f"[WARN] RTT ölçülemedi, varsayılan gecikme kullanılacak: {e}")
        return 100

def print_progress(current, total):
    bar_len = 40
    filled = int(bar_len * current / total)
    bar = "=" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\rProgress: [{bar}] {current}/{total}\n")
    sys.stdout.flush()

def send_file_udp(file_path, ip='127.0.0.1', port=9000):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    filename = os.path.basename(file_path).encode()
    with open(file_path, 'rb') as f:
        data = f.read()

    log_message("[UDP] Dosya gönderimine başlandı.")
    log_message(f"[UDP] Gönderilen dosya: {file_path}, boyut: {len(data)} byte")

    max_chunk_size = 1400
    total_chunks = (len(data) + max_chunk_size - 1) // max_chunk_size

    for i in range(total_chunks):
        chunk = data[i*max_chunk_size : (i+1)*max_chunk_size]
        header = len(filename).to_bytes(4, 'big') + filename + i.to_bytes(4, 'big') + total_chunks.to_bytes(4, 'big')
        packet = header + chunk
        sock.sendto(packet, (ip, port))
        print(f"[UDP] Chunk {i+1}/{total_chunks} gönderildi.")
        log_message(f"[UDP] Chunk {i+1}/{total_chunks} gönderildi.")
        time.sleep(0.01)

    sock.close()
    print("[UDP] Tüm parçalar gönderildi.")
    log_message(f"[UDP] Tüm {total_chunks} parça gönderildi.")
    log_message(f"[SUMMARY] UDP ile gönderilen dosya: {file_path}, Parça sayısı: {total_chunks}")



def send_file(file_path, ip='127.0.0.1', port=9000):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            log_message(f"[CONNECT] Connected to {ip}:{port}")
            auth_data = SHARED_SECRET.encode()
            s.sendall(len(auth_data).to_bytes(4, byteorder='big'))
            s.sendall(auth_data)

            aes_key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)

            with open(PUBLIC_KEY_FILE, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            s.sendall(len(encrypted_aes_key).to_bytes(4, byteorder='big'))
            s.sendall(encrypted_aes_key)
            s.sendall(iv)
            log_message("[KEY] AES anahtarı RSA ile şifrelenip gönderildi.")

            filename = os.path.basename(file_path).encode()
            s.sendall(f"{len(filename):04d}".encode())
            s.sendall(filename)
            log_message(f"[INFO] Sending file: {file_path} as {filename.decode()}")

            with open(file_path, 'rb') as f:
                fragments = []
                while True:
                    chunk = f.read(FRAGMENT_SIZE)
                    if not chunk:
                        break
                    fragments.append(chunk)

            total_fragments = len(fragments)
            s.sendall(total_fragments.to_bytes(4, byteorder='big'))
            log_message(f"[INFO] Total fragments: {total_fragments}")

            sent_fragments = 0
            for fragment_id, chunk in enumerate(fragments):
                if fragment_id in SKIP_FRAGMENTS:
                    print(f"[!] ⛔ Skipped Fragment {fragment_id}")
                    log_message(f"[SKIP] Fragment {fragment_id} skipped manually.")
                    continue

                try:
                    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()

                    hash_digest = hashlib.sha256(encrypted_chunk).digest()
                    fragment_header = fragment_id.to_bytes(4, byteorder='big')
                    packet = fragment_header + encrypted_chunk + hash_digest
                    s.sendall(packet)

                    ip_layer = IP(dst=ip, ttl=42, flags="DF", id=random.randint(1000, 9999), chksum=0)
                    tcp_layer = TCP(dport=port, sport=random.randint(1024, 65535), flags="PA", seq=random.randint(1000, 99999))
                    temp_ip_packet = ip_layer / tcp_layer / Raw(load=packet)
                    ip_raw = bytes(temp_ip_packet)[:20]
                    manual_checksum = calculate_checksum(ip_raw)
                    ip_layer.chksum = manual_checksum

                    scapy_packet = ip_layer / tcp_layer / Raw(load=packet)
                    send(scapy_packet, iface=SCAPY_IFACE, verbose=False)

                    print(f"[>] ✅ Sent Fragment {fragment_id} (with modified IP header)")
                    log_message(f"[FRAGMENT] Sent Fragment {fragment_id} successfully.")

                    rtt = get_rtt(ip)
                    delay = min(max(rtt / 1000, 0.01), 0.3)
                    log_message(f"[ADAPT] RTT: {rtt}ms → Sleep: {delay:.3f}s")
                    time.sleep(delay)

                    sent_fragments += 1
                    print_progress(sent_fragments, total_fragments)

                except Exception as fragment_error:
                    print(f"[!] Hata: Fragment {fragment_id} gönderilemedi. Sebep: {fragment_error}")
                    log_message(f"[ERROR] Fragment {fragment_id} gönderilemedi: {fragment_error}")
                    continue

            print(f"[i] Total fragments in memory: {len(fragments)}")
            print(f"\n[+] File sent with fragmentation and AES/RSA encryption.")
            print(f"[i] Sent {sent_fragments}/{total_fragments} fragments.")
            log_message(f"[SUMMARY] File sent: {file_path}, Fragments Sent: {sent_fragments}/{total_fragments}")
            print(f"[i] Gönderilecek fragment ID'leri: {list(range(len(fragments)))}")

    except ConnectionResetError:
        print("[❌] Bağlantı karşı sunucu tarafından kapatıldı! (Hatalı şifre?)")
    except Exception as e:
        print(f"[❗] Beklenmeyen hata: {e}")
        log_message(f"[EXCEPTION] Unexpected error: {e}")

def dynamic_send(file_path, ip='127.0.0.1', port=9000):
    rtt = get_rtt(ip)
    print(f"[RTT] {rtt}ms ölçüldü.")
    if rtt > 100:
        print("[ADAPT] RTT yüksek, UDP ile gönderiliyor.")
        send_file_udp(file_path, ip, port)
    else:
        print("[ADAPT] RTT düşük, TCP ile güvenli gönderiliyor.")
        send_file(file_path, ip, port)

if __name__ == "__main__":
    dynamic_send("example.txt")
