package mail

import (
	"fmt"
	"net/smtp"
	"net/url"

	"github.com/cwkr/authd/internal/stringutil"
)

type Mailer interface {
	SendMail(to string, subject string, text string) error
}

type simpleMailer struct {
	host string
	from string
	auth smtp.Auth
}

func (s simpleMailer) SendMail(to string, subject string, content string) error {
	var body = fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html;charset=UTF-8\r\n\r\n%s",
		s.from,
		to,
		subject,
		content,
	)
	return smtp.SendMail(s.host, s.auth, s.from, []string{to}, []byte(body))
}

func NewMailer(settings MailSettings) (Mailer, error) {
	if mailURL, err := url.Parse(settings.ServerURI); err != nil {
		return nil, err
	} else {
		var (
			auth     smtp.Auth
			username string
		)
		if mailURL.User != nil {
			var password, _ = mailURL.User.Password()
			username = mailURL.User.Username()
			auth = smtp.PlainAuth("", username, password, mailURL.Hostname())
		}
		return &simpleMailer{
			host: mailURL.Host,
			from: stringutil.FirstNonEmpty(settings.From, username),
			auth: auth,
		}, nil
	}
}
