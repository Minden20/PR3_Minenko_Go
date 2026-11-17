#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "=== Генерація сертифікатів PKI для mTLS ==="

if command -v openssl >/dev/null 2>&1; then
    echo "[OpenSSL] Використання openssl..."

    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 -subj "/CN=MyRootCA"

    openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 \
      -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth")
    rm -f server.csr

    openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=dispatcher-agent-01"
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 \
      -extfile <(printf "extendedKeyUsage=clientAuth")
    rm -f client.csr

    echo "Сертифікати згенеровано за допомогою OpenSSL!"
else
    echo "[Go PKI] OpenSSL не знайдено, використовується генератор Go..."
    go run generate_certs.go .
    echo "Сертифікати згенеровано за допомогою Go PKI!"
fi

