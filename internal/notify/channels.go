// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/policy"
)

// Channel delivers messages.
type Channel interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

// Ntfy publishes via ntfy's JSON API (POST to the server root with the
// topic in the body, which keeps UTF-8 titles intact).
type Ntfy struct {
	HTTP  *httpx.Client
	URL   string // https://ntfy.example.com/topic
	Token string
}

// Name implements Channel.
func (*Ntfy) Name() string { return "ntfy" }

// Send implements Channel.
func (n *Ntfy) Send(ctx context.Context, m Message) error {
	u, err := url.Parse(n.URL)
	if err != nil {
		return fmt.Errorf("ntfy url: %w", err)
	}
	topic := strings.Trim(u.Path, "/")
	if topic == "" || strings.Contains(topic, "/") {
		return errors.New("ntfy url must end with a single topic, e.g. https://ntfy.example.com/varde")
	}
	u.Path = "/"
	body, err := json.Marshal(map[string]any{
		"topic":    topic,
		"title":    m.Title,
		"message":  m.Body,
		"priority": ntfyPriority(m),
	})
	if err != nil {
		return err
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if n.Token != "" {
		h.Set("Authorization", "Bearer "+n.Token)
	}
	_, err = n.HTTP.Do(ctx, httpx.Request{Method: http.MethodPost, URL: u.String(), Body: body, Header: h, MaxBytes: 64 << 10})
	return err
}

func ntfyPriority(m Message) int {
	switch m.Priority {
	case policy.P1:
		return 5
	case policy.P2:
		return 3
	case policy.P3:
		return 2
	}
	return 3
}

// Gotify posts to /message with the application token in a header, never
// in the URL.
type Gotify struct {
	HTTP  *httpx.Client
	URL   string // https://gotify.example.com
	Token string
}

// Name implements Channel.
func (*Gotify) Name() string { return "gotify" }

// Send implements Channel.
func (g *Gotify) Send(ctx context.Context, m Message) error {
	prio := 5
	switch m.Priority {
	case policy.P1:
		prio = 8
	case policy.P3:
		prio = 2
	}
	body, err := json.Marshal(map[string]any{"title": m.Title, "message": m.Body, "priority": prio})
	if err != nil {
		return err
	}
	h := http.Header{"Content-Type": {"application/json"}, "X-Gotify-Key": {g.Token}}
	_, err = g.HTTP.Do(ctx, httpx.Request{Method: http.MethodPost, URL: strings.TrimRight(g.URL, "/") + "/message", Body: body, Header: h, MaxBytes: 64 << 10})
	return err
}

// Webhook posts the message as JSON. With a secret, it signs
// "<timestamp>.<body>" with HMAC-SHA256 so receivers can verify origin and
// reject replays.
type Webhook struct {
	HTTP   *httpx.Client
	URL    string
	Secret string
	Now    func() time.Time
}

// Webhook signature headers.
const (
	HeaderTimestamp = "X-Varde-Timestamp"
	HeaderSignature = "X-Varde-Signature"
)

// Name implements Channel.
func (*Webhook) Name() string { return "webhook" }

// Send implements Channel.
func (w *Webhook) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(struct {
		Version int `json:"version"`
		Message
	}{1, m})
	if err != nil {
		return err
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if w.Secret != "" {
		now := time.Now
		if w.Now != nil {
			now = w.Now
		}
		ts := strconv.FormatInt(now().Unix(), 10)
		h.Set(HeaderTimestamp, ts)
		h.Set(HeaderSignature, "sha256="+Sign(w.Secret, ts, body))
	}
	_, err = w.HTTP.Do(ctx, httpx.Request{Method: http.MethodPost, URL: w.URL, Body: body, Header: h, MaxBytes: 64 << 10})
	return err
}

// Sign computes the webhook signature (hex HMAC-SHA256 of "ts.body").
func Sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SMTP TLS modes.
const (
	SMTPStartTLS = "starttls"
	SMTPTLS      = "tls"
	SMTPNone     = "none"
)

// SMTP sends plain-text mail.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	TLSMode  string
	// RootCAs overrides the trust store (tests).
	TLSConfig *tls.Config
	Now       func() time.Time
}

// Name implements Channel.
func (*SMTP) Name() string { return "smtp" }

// Send implements Channel.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	tlsCfg := s.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tlsCfg = tlsCfg.Clone()
	tlsCfg.ServerName = s.Host

	dialer := &net.Dialer{Timeout: 10 * time.Second, Deadline: deadline}
	var conn net.Conn
	var err error
	if s.TLSMode == SMTPTLS {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp connect: %w", err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello("varde"); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if s.TLSMode == SMTPStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp server does not offer STARTTLS; refusing to send credentials in clear text")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if s.Username != "" {
		// net/smtp refuses PLAIN auth over unencrypted connections to
		// remote hosts, which matches the intended policy.
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range s.To {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(s.render(m)); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return c.Quit()
}

func (s *SMTP) render(m Message) []byte {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	t := now()
	var b strings.Builder
	header := func(k, v string) {
		b.WriteString(k + ": " + clean(v, 900) + "\r\n")
	}
	header("From", s.From)
	header("To", strings.Join(s.To, ", "))
	header("Subject", encodeHeader(m.Title))
	header("Date", t.Format(time.RFC1123Z))
	header("Message-ID", fmt.Sprintf("<%d.%s@%s>", t.UnixNano(), buildinfo.ID, s.Host))
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	for _, line := range strings.Split(m.Body, "\n") {
		// Dot-stuffing is done by net/smtp's data writer; only normalise
		// line endings here.
		b.WriteString(strings.TrimRight(line, "\r") + "\r\n")
	}
	return []byte(b.String())
}

// encodeHeader uses RFC 2047 for non-ASCII subjects (ASCII passes as is).
func encodeHeader(s string) string { return mime.QEncoding.Encode("utf-8", s) }
