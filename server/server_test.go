package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pr3_minenko/email"
)

type testSMTPServer struct {
	listener     net.Listener
	addr         string
	receivedMsgs []string
	mu           sync.Mutex
}

func startTestSMTP(t *testing.T) *testSMTPServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for test SMTP: %v", err)
	}

	s := &testSMTPServer{
		listener: l,
		addr:     l.Addr().String(),
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := bufio.NewWriter(c)
				w.WriteString("220 test-smtp ESMTP Ready\r\n")
				w.Flush()

				var inData bool
				var dataLines []string

				for {
					line, err := r.ReadString('\n')
					if err != nil {
						break
					}
					clean := strings.TrimRight(line, "\r\n")
					if inData {
						if clean == "." {
							inData = false
							w.WriteString("250 2.0.0 Ok\r\n")
							w.Flush()
							s.mu.Lock()
							s.receivedMsgs = append(s.receivedMsgs, strings.Join(dataLines, "\n"))
							s.mu.Unlock()
							dataLines = nil
						} else {
							dataLines = append(dataLines, clean)
						}
						continue
					}
					upper := strings.ToUpper(clean)
					switch {
					case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
						w.WriteString("250-test-smtp Hello\r\n250 SIZE 1048576\r\n")
						w.Flush()
					case strings.HasPrefix(upper, "MAIL FROM:"):
						w.WriteString("250 Ok\r\n")
						w.Flush()
					case strings.HasPrefix(upper, "RCPT TO:"):
						w.WriteString("250 Ok\r\n")
						w.Flush()
					case upper == "DATA":
						inData = true
						w.WriteString("354 Start mail input\r\n")
						w.Flush()
					case upper == "QUIT":
						w.WriteString("221 Bye\r\n")
						w.Flush()
						return
					}
				}
			}(conn)
		}
	}()

	return s
}

func (s *testSMTPServer) close() {
	s.listener.Close()
}

func TestMTLSServerAndClientLevel1AndLevel2(t *testing.T) {

	smtpSrv := startTestSMTP(t)
	defer smtpSrv.close()

	host, port, _ := net.SplitHostPort(smtpSrv.addr)
	mailer := email.NewMailer(host, port, "alert-gateway@internal.net", nil)

	certDir := filepath.Join("..", "certs")
	serverCert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "server.crt"), filepath.Join(certDir, "server.key"))
	if err != nil {
		t.Fatalf("Failed to load server cert: %v", err)
	}

	caCertBytes, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatalf("Failed to read ca.crt: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertBytes)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("Failed to listen mTLS: %v", err)
	}
	defer l.Close()

	serverAddr := l.Addr().String()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleClient(conn, mailer)
		}
	}()

	clientCert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "client.crt"), filepath.Join(certDir, "client.key"))
	if err != nil {
		t.Fatalf("Failed to load client cert: %v", err)
	}

	clientConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, clientConf)
	if err != nil {
		t.Fatalf("Client failed to dial server: %v", err)
	}

	alertMsg := "CRITICAL_ERROR: Database connection timeout on node-04\n"
	_, err = conn.Write([]byte(alertMsg))
	if err != nil {
		t.Fatalf("Failed to write alert: %v", err)
	}

	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read server response: %v", err)
	}
	conn.Close()

	if !strings.Contains(resp, "ALERT PROCESSED AND DISPATCHED") && !strings.Contains(resp, "ALERT RECEIVED AND VERIFIED") {
		t.Errorf("Unexpected server response: %s", resp)
	}

	time.Sleep(200 * time.Millisecond)
	smtpSrv.mu.Lock()
	if len(smtpSrv.receivedMsgs) == 0 {
		t.Errorf("Expected SMTP email to be dispatched, but received 0")
	} else {
		received := smtpSrv.receivedMsgs[0]
		if !strings.Contains(received, "CRITICAL_ERROR: Database connection timeout on node-04") {
			t.Errorf("Email body does not contain alert text: %s", received)
		}
		if !strings.Contains(received, "dispatcher-agent-01") {
			t.Errorf("Email body does not contain client CN: %s", received)
		}
	}
	smtpSrv.mu.Unlock()

	unauthConf := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
	}
	unauthConn, err := tls.Dial("tcp", serverAddr, unauthConf)
	if err == nil {
		_, readErr := io.ReadAll(unauthConn)
		unauthConn.Close()
		if readErr == nil {
			t.Errorf("Expected unauthorized connection to fail TLS handshake, but it succeeded")
		}
	}
}
