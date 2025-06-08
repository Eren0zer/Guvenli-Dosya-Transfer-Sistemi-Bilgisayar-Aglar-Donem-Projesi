#!/bin/bash

INTERFACE="enp0s3"  # Burayı kendi arayüz adına göre değiştir

echo "✅ tc ile simülasyon başlatılıyor..."

# 1. Paket kaybı: %20
sudo tc qdisc add dev $INTERFACE root netem loss 20%

echo "[•] %20 paket kaybı simülasyonu başladı."
sleep 3

# 2. Gecikme: 100ms
sudo tc qdisc change dev $INTERFACE root netem delay 100ms

echo "[•] 100ms gecikme eklendi."
sleep 3

# 3. Gecikme + kayıp birlikte
sudo tc qdisc change dev $INTERFACE root netem delay 100ms loss 10%

echo "[•] Hem gecikme hem %10 kayıp simülasyonu aktif."
sleep 5

# Temizle
sudo tc qdisc del dev $INTERFACE root netem
echo "✅ Simülasyon sona erdi, ağ normale döndü."
