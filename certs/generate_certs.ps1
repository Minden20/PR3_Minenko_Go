$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

Write-Host "=== Генерація сертифікатів PKI для mTLS ===" -ForegroundColor Cyan

$opensslCmd = Get-Command "openssl" -ErrorAction SilentlyContinue

if ($opensslCmd) {
    Write-Host "[OpenSSL] Використання OpenSSL..." -ForegroundColor Green
    
    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 -subj "/CN=MyRootCA"

    openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
    $serverExt = "subjectAltName=DNS:localhost,IP:127.0.0.1`nextendedKeyUsage=serverAuth"
    $serverExt | Out-File -FilePath "server_ext.cnf" -Encoding ascii
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extfile server_ext.cnf
    Remove-Item "server.csr", "server_ext.cnf" -ErrorAction SilentlyContinue

    openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=dispatcher-agent-01"
    $clientExt = "extendedKeyUsage=clientAuth"
    $clientExt | Out-File -FilePath "client_ext.cnf" -Encoding ascii
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -extfile client_ext.cnf
    Remove-Item "client.csr", "client_ext.cnf" -ErrorAction SilentlyContinue

    Write-Host "Сертифікати успішно згенеровано через OpenSSL!" -ForegroundColor Green
} else {
    Write-Host "[Go PKI] OpenSSL не знайдено в PATH, запускається генератор на Go..." -ForegroundColor Yellow
    go run generate_certs.go .
    Write-Host "Сертифікати успішно згенеровано через Go PKI!" -ForegroundColor Green
}

