package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"pr3_minenko/email"
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
	serverPort := "8443"
	smtpHost := "127.0.0.1"
	smtpPort := "1025"

	if val := os.Getenv("SERVER_PORT"); val != "" {
		serverPort = val
	}
	if val := os.Getenv("SMTP_HOST"); val != "" {
		smtpHost = val
	}
	if val := os.Getenv("SMTP_PORT"); val != "" {
		smtpPort = val
	}

	fmt.Println("================================================================================")
	fmt.Printf("=== Захищений шлюз критичних сповіщень (mTLS: %s, SMTP Target: %s) ===\n", serverPort, smtpPort)
	fmt.Println("================================================================================")

	serverCertPath := findCertPath("server.crt")
	serverKeyPath := findCertPath("server.key")
	caCertPath := findCertPath("ca.crt")

	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Не вдалося завантажити сертифікат сервера (%s, %s): %v\n", serverCertPath, serverKeyPath, err)
		os.Exit(1)
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Не вдалося прочитати Root CA (%s): %v\n", caCertPath, err)
		os.Exit(1)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		fmt.Println("[ПОМИЛКА] Не вдалося додати ca.crt до пулу сертифікатів")
		os.Exit(1)
	}
	fmt.Printf("[СЕРВЕР] Пул CA завантажено: %s (1 сертифікат)\n", caCertPath)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", ":"+serverPort, serverTLSConfig)
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Не вдалося відкрити mTLS слухач на :%s: %v\n", serverPort, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("[СЕРВЕР] Слухач mTLS відкрито на порту :%s (TLS 1.3, ClientAuth=RequireAndVerify)\n", serverPort)

	mailer := email.NewMailer(smtpHost, smtpPort, "alert-gateway@internal.net", nil)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("[ПОМИЛКА] Помилка прийняття з'єднання: %v\n", err)
			continue
		}

		go handleClient(conn, mailer)
	}
}

func handleClient(conn net.Conn, mailer *email.Mailer) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	fmt.Printf("\n[ПІДКЛЮЧЕННЯ] Встановлено TLS-з'єднання від %s\n", remoteAddr)

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		fmt.Println("[ПОМИЛКА] Невірний тип TLS з'єднання")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("[ВІДХИЛЕНО] Неавторизований клієнт з %s (помилка mTLS рукостискання): %v\n", remoteAddr, err)
		return
	}

	state := tlsConn.ConnectionState()
	clientCN := "Unknown"
	var serialStr string

	if len(state.PeerCertificates) > 0 {
		clientCert := state.PeerCertificates[0]
		clientCN = clientCert.Subject.CommonName
		serialStr = clientCert.SerialNumber.String()
		fmt.Printf("[АУДИТ ZERO TRUST] Клієнт верифікований: CN=%s, Серійний номер=%s\n", clientCN, serialStr)
	} else {
		fmt.Println("[УВАГА] Клієнтський сертифікат відсутній у PeerCertificates")
	}

	reader := bufio.NewReader(conn)
	message, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[ПОМИЛКА] Помилка читання повідомлення від %s: %v\n", remoteAddr, err)
		return
	}
	message = strings.TrimSpace(message)

	fmt.Printf("[ПОВІДОМЛЕННЯ] Отримано інцидент: %s\n", message)

	recipient := "duty-engineer@internal.net"
	subject := fmt.Sprintf("[ALARM] %s від %s", message, clientCN)

	fmt.Printf("[SMTP] Надсилання email на %s через %s:%s...\n", recipient, mailer.Host, mailer.Port)
	emailErr := mailer.SendAlert([]string{recipient}, subject, message, clientCN)
	if emailErr != nil {
		fmt.Printf("[SMTP] Помилка надсилання email: %v\n", emailErr)
	} else {
		fmt.Println("[SMTP] Лист про аварію успішно доставлено до поштового шлюзу!")
	}

	response := "[SERVER]: ALERT RECEIVED AND VERIFIED\n"
	if emailErr == nil {
		response = "[SERVER]: ALERT PROCESSED AND DISPATCHED\n"
	}
	_, _ = conn.Write([]byte(response))
	fmt.Printf("[ВІДПОВІДЬ] Клієнту надіслано статус: %s", response)
	fmt.Printf("[СЕСІЯ] З'єднання з %s успішно закрито.\n", remoteAddr)
}
