package email

import (
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

type Mailer struct {
	Host string
	Port string
	From string
	Auth smtp.Auth
}

func NewMailer(host, port, from string, auth smtp.Auth) *Mailer {
	return &Mailer{
		Host: host,
		Port: port,
		From: from,
		Auth: auth,
	}
}

func (m *Mailer) SendAlert(to []string, subject, incidentText string, clientCN string) error {
	addr := fmt.Sprintf("%s:%s", m.Host, m.Port)
	now := time.Now().Format(time.RFC1123Z)

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", m.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Date: %s\r\n", now))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("\r\n")

	msg.WriteString("=== ТРИВОГА: СИСТЕМА КРИТИЧНИХ СПОВІЩЕНЬ (SECURE ALERT GATEWAY) ===\r\n\r\n")
	msg.WriteString(fmt.Sprintf("Час реєстрації: %s\r\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	if clientCN != "" {
		msg.WriteString(fmt.Sprintf("Джерело (Клієнт mTLS): %s\r\n", clientCN))
	}
	msg.WriteString("Рівень небезпеки: CRITICAL\r\n\r\n")
	msg.WriteString("Деталі інциденту:\r\n")
	msg.WriteString(incidentText)
	msg.WriteString("\r\n\r\n---\r\n")
	msg.WriteString("Це повідомлення згенеровано автоматично сервісом безпеки mTLS.\r\n")

	err := smtp.SendMail(addr, m.Auth, m.From, to, []byte(msg.String()))
	if err != nil {
		return fmt.Errorf("помилка smtp.SendMail на %s: %w", addr, err)
	}

	return nil
}
