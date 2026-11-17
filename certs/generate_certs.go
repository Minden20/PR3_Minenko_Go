package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := "."
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Помилка створення папки: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Генерація PKI інфраструктури (X.509 / mTLS) ===")

	fmt.Println("[1/3] Створення Root CA (ca.key, ca.crt)...")
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(20260001),
		Subject: pkix.Name{
			CommonName:   "MyRootCA",
			Organization: []string{"Secure Alert Gateway CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}

	savePEM(filepath.Join(outDir, "ca.crt"), "CERTIFICATE", caBytes)
	savePEM(filepath.Join(outDir, "ca.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caPrivKey))

	fmt.Println("[2/3] Створення сертифіката сервера (server.key, server.crt)...")
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(20260002),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Secure Alert Gateway Server"},
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serverBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}

	savePEM(filepath.Join(outDir, "server.crt"), "CERTIFICATE", serverBytes)
	savePEM(filepath.Join(outDir, "server.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverPrivKey))

	fmt.Println("[3/3] Створення сертифіката клієнта (client.key, client.crt)...")
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(20260003),
		Subject: pkix.Name{
			CommonName:   "dispatcher-agent-01",
			Organization: []string{"Emergency Dispatcher Agent"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		panic(err)
	}

	savePEM(filepath.Join(outDir, "client.crt"), "CERTIFICATE", clientBytes)
	savePEM(filepath.Join(outDir, "client.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientPrivKey))

	fmt.Println("Успішно! Усі сертифікати збережено в папці:", outDir)
}

func savePEM(filename, blockType string, bytes []byte) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: bytes}); err != nil {
		panic(err)
	}
}
