package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	port := "1025"
	if val := os.Getenv("SMTP_PORT"); val != "" {
		port = val
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Printf("[MOCK-SMTP] Помилка відкриття порту %s: %v\n", port, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("================================================================================")
	fmt.Printf("=== Локальний тестовий SMTP емулятор запущено на порту :%s ===\n", port)
	fmt.Println("=== Очікування вхідних email повідомлень від mTLS сервера...                 ===")
	fmt.Println("================================================================================")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("[MOCK-SMTP] Помилка з'єднання: %v\n", err)
			continue
		}
		go handleSMTP(conn)
	}
}

func handleSMTP(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writer.WriteString("220 mock-smtp.local ESMTP Mock Mail Server Ready\r\n")
	writer.Flush()

	var inData bool
	var dataLines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		cleanLine := strings.TrimRight(line, "\r\n")

		if inData {
			if cleanLine == "." {
				inData = false
				writer.WriteString("250 2.0.0 Ok: queued\r\n")
				writer.Flush()

				fmt.Println("\n-------------------- [MOCK-SMTP: Отримано новий лист] --------------------")
				fmt.Printf("Час доставки: %s\n", time.Now().Format("2006-01-02 15:04:05"))
				for _, dl := range dataLines {
					fmt.Println(dl)
				}
				fmt.Println("--------------------------------------------------------------------------")
				fmt.Println()
				dataLines = nil
			} else {
				dataLines = append(dataLines, cleanLine)
			}
			continue
		}

		upper := strings.ToUpper(cleanLine)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			writer.WriteString("250-mock-smtp.local Hello\r\n250 SIZE 10485760\r\n")
			writer.Flush()
		case strings.HasPrefix(upper, "MAIL FROM:"):
			writer.WriteString("250 2.1.0 Ok\r\n")
			writer.Flush()
		case strings.HasPrefix(upper, "RCPT TO:"):
			writer.WriteString("250 2.1.5 Ok\r\n")
			writer.Flush()
		case upper == "DATA":
			inData = true
			writer.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n")
			writer.Flush()
		case upper == "RSET":
			writer.WriteString("250 2.0.0 Ok\r\n")
			writer.Flush()
		case upper == "NOOP":
			writer.WriteString("250 2.0.0 Ok\r\n")
			writer.Flush()
		case upper == "QUIT":
			writer.WriteString("221 2.0.0 Bye\r\n")
			writer.Flush()
			return
		default:
			writer.WriteString("500 5.5.2 Syntax error, command unrecognized\r\n")
			writer.Flush()
		}
	}
}
