#!/bin/bash
set -e

PORT_LAMA=80
PORT_BARU=8081

echo "=== Mengubah port Apache2 ke ${PORT_BARU} ==="

# Pastikan dijalankan sebagai root
if [ "$EUID" -ne 0 ]; then
    echo "Jalankan script sebagai root!"
    exit 1
fi

# Backup konfigurasi sebelum perubahan
BACKUP="/root/backup-apache-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"

cp -a /etc/apache2/ports.conf "$BACKUP/"
cp -a /etc/apache2/sites-available "$BACKUP/"

echo "Backup konfigurasi: $BACKUP"

# Ubah Listen 80 menjadi Listen 8081
sed -i -E \
's/^[[:space:]]*Listen[[:space:]]+80[[:space:]]*$/Listen 8081/' \
/etc/apache2/ports.conf

# Ubah VirtualHost *:80 menjadi *:8081
if [ -f /etc/apache2/sites-available/000-default.conf ]; then
    sed -i \
's/<VirtualHost \*:80>/<VirtualHost *:8081>/' \
/etc/apache2/sites-available/000-default.conf
fi

# Periksa konfigurasi Apache
echo
echo "=== Memeriksa konfigurasi Apache2 ==="

if apache2ctl configtest; then
    echo
    echo "=== Restart Apache2 ==="
    systemctl restart apache2

    echo
    systemctl --no-pager --full status apache2

    echo
    echo "=== Port yang sedang digunakan ==="
    ss -lntp | grep -E ':(80|8080|8081)\b' || true

    echo
    echo "Selesai. Apache2 diarahkan ke port 8081."
    echo "Uji akses: http://IP-SERVER:8081/"
else
    echo
    echo "ERROR: Konfigurasi tidak valid."
    echo "Backup tersedia di: $BACKUP"
    echo "Apache2 tidak direstart oleh script."
    exit 1
fi
