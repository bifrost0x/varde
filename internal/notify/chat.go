// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/bifrost0x/varde/internal/httpx"
)

// Chat services take the secret in the URL path (a Discord webhook URL, a
// Telegram bot token), where httpx does not redact it; their errors are
// redacted here before they reach logs or the UI.

// Discord posts to a Discord webhook. Mentions are switched off: advisory
// text must not ping a server.
type Discord struct {
	HTTP *httpx.Client
	// URL is the webhook URL, a secret.
	URL string
}

// Name implements Channel.
func (*Discord) Name() string { return "discord" }

// discordLimit is Discord's message length.
const discordLimit = 2000

// Send implements Channel.
func (d *Discord) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(map[string]any{
		"content":          clip("**"+escapeDiscord(m.Title)+"**\n"+escapeDiscord(m.Body), discordLimit),
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	if err != nil {
		return err
	}
	_, err = d.HTTP.Do(ctx, httpx.Request{Method: http.MethodPost, URL: d.URL, Body: body,
		Header: http.Header{"Content-Type": {"application/json"}}, MaxBytes: 64 << 10})
	return redactWebhook(redact(err, d.URL, "<webhook url>"))
}

// webhookToken matches the token part of a Discord webhook path, however
// the URL was printed (normalised, as a redirect target).
var webhookToken = regexp.MustCompile(`/webhooks/[0-9]+/[A-Za-z0-9_.%-]+`)

func redactWebhook(err error) error {
	if err == nil {
		return nil
	}
	return &patternError{err: err}
}

// patternError hides webhook tokens in an error's text.
type patternError struct{ err error }

func (p *patternError) Error() string {
	return webhookToken.ReplaceAllString(p.err.Error(), "/webhooks/<id>/<token>")
}
func (p *patternError) Unwrap() error { return p.err }

// escapeDiscord keeps upstream text from forming Markdown links or
// formatting.
func escapeDiscord(s string) string {
	return strings.NewReplacer("\\", "\\\\", "*", "\\*", "_", "\\_", "`", "\\`", "~", "\\~", "|", "\\|", ">", "\\>", "[", "\\[", "]", "\\]").Replace(s)
}

// Telegram sends through the Telegram Bot API as plain text.
type Telegram struct {
	HTTP *httpx.Client
	// Token is the bot token, a secret; ChatID the chat to write to.
	Token, ChatID string
	// BaseURL replaces https://api.telegram.org in tests.
	BaseURL string
}

// Name implements Channel.
func (*Telegram) Name() string { return "telegram" }

// telegramLimit is Telegram's message length.
const telegramLimit = 4096

// Send implements Channel.
func (t *Telegram) Send(ctx context.Context, m Message) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	// No parse mode: advisory text is sent as it is, never as markup.
	body, err := json.Marshal(map[string]any{
		"chat_id": t.ChatID, "text": clip(m.Title+"\n\n"+m.Body, telegramLimit), "disable_web_page_preview": true,
	})
	if err != nil {
		return err
	}
	_, err = t.HTTP.Do(ctx, httpx.Request{Method: http.MethodPost, URL: base + "/bot" + t.Token + "/sendMessage", Body: body,
		Header: http.Header{"Content-Type": {"application/json"}}, MaxBytes: 64 << 10})
	return redact(err, t.Token, "<token>")
}

// clip shortens s to n bytes without cutting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	n -= len("…")
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// redactedError hides a secret in an error's text; Unwrap keeps the cause
// for status checks.
type redactedError struct {
	err            error
	secret, marker string
}

func (r *redactedError) Error() string { return strings.ReplaceAll(r.err.Error(), r.secret, r.marker) }
func (r *redactedError) Unwrap() error { return r.err }

func redact(err error, secret, marker string) error {
	if err == nil || secret == "" {
		return err
	}
	var re *redactedError
	if errors.As(err, &re) {
		return err
	}
	return &redactedError{err: err, secret: secret, marker: marker}
}
