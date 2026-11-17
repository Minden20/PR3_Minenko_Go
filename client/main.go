package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func findCertPath(file string) string {
	candidates := []string{
		filepath.Join("certs", file),
		filepath.Join("..", "certs", file),
		file,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join("certs", file)
}

func main() {
	serverAddr := "127.0.0.1:8443"
	if val := os.Getenv("SERVER_ADDR"); val != "" {
		serverAddr = val
	}

	fmt.Println("================================================================================")
	fmt.Println("=== Агент диспетчеризації (mTLS Client) ===")
	fmt.Println("================================================================================")

	clientCertPath := findCertPath("client.crt")
	clientKeyPath := findCertPath("client.key")
	caCertPath := findCertPath("ca.crt")

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Не вдалося завантажити сертифікат клієнта (%s, %s): %v\n", clientCertPath, clientKeyPath, err)
		os.Exit(1)
	}
	fmt.Printf("[КЛІЄНТ] Завантажено сертифікат клієнта: %s (CN=dispatcher-agent-01)\n", clientCertPath)

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Не вдалося прочитати Root CA (%s): %v\n", caCertPath, err)
		os.Exit(1)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		fmt.Println("[ПОМИЛКА] Не вдалося додати ca.crt до пулу довірених CA")
		os.Exit(1)
	}
	fmt.Printf("[КЛІЄНТ] Завантажено довірений Root CA: %s\n", caCertPath)

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	fmt.Printf("[КЛІЄНТ] Підключення до шлюзу %s...\n", serverAddr)
	conn, err := tls.Dial("tcp", serverAddr, clientTLSConfig)
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Помилка встановлення mTLS з'єднання: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var tlsVer string
	switch state.Version {
	case tls.VersionTLS13:
		tlsVer = "TLS 1.3"
	case tls.VersionTLS12:
		tlsVer = "TLS 1.2"
	default:
		tlsVer = fmt.Sprintf("0x%04x", state.Version)
	}
	fmt.Printf("[КЛІЄНТ] mTLS-рукостискання успішне. Використано протокол %s\n", tlsVer)

	incidentMsg := "CRITICAL_ERROR: Database connection timeout on node-04"
	if len(os.Args) > 1 {
		incidentMsg = strings.Join(os.Args[1:], " ")
	}

	fmt.Printf("[КЛІЄНТ] Відправка алерту: %s\n", incidentMsg)
	_, err = fmt.Fprintf(conn, "%s\n", incidentMsg)
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Помилка відправки даних: %v\n", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Помилка читання відповіді сервера: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[КЛІЄНТ] Відповідь від сервера: %s", response)
	fmt.Println("[КЛІЄНТ] Сесію успішно завершено.")
}
