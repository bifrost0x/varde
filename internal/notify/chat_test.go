// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
)

func TestDiscord(t *testing.T) {
	var got map[string]any
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	hc := httpx.New(httpx.Options{AllowHTTP: true, Timeout: 5 * time.Second})
	url := srv.URL + "/api/webhooks/123/s3cr3t-webhook-token"
	d := &Discord{HTTP: hc, URL: url}
	if err := d.Send(t.Context(), Message{Title: "P1: immich", Body: "@everyone [click](https://evil) " + strings.Repeat("x", 3000)}); err != nil {
		t.Fatal(err)
	}
	content, _ := got["content"].(string)
	if len(content) > discordLimit || !strings.HasPrefix(content, "**P1: immich**") || !strings.Contains(content, `\[click\]`) {
		t.Errorf("content: %.200q", content)
	}
	am, _ := got["allowed_mentions"].(map[string]any)
	if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 {
		t.Errorf("mentions not switched off: %v", got["allowed_mentions"])
	}
	status = http.StatusUnauthorized
	err := d.Send(t.Context(), Message{Title: "x"})
	if err == nil || strings.Contains(err.Error(), "s3cr3t-webhook-token") {
		t.Errorf("token in error: %v", err)
	}
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		t.Errorf("status lost: %v", err)
	}
	// Also when the error prints the URL in another form.
	if got := redactWebhook(errors.New("Post https://discord.com/api/webhooks/123/abc%2Ddef: refused")).Error(); strings.Contains(got, "abc") {
		t.Errorf("token in normalised URL: %s", got)
	}
}

func TestTelegram(t *testing.T) {
	var got map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		if strings.Contains(path, "wrong") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	hc := httpx.New(httpx.Options{AllowHTTP: true, Timeout: 5 * time.Second})
	tg := &Telegram{HTTP: hc, Token: "123456:abcdefghijklmnopqrstuvwxyz", ChatID: "-1001", BaseURL: srv.URL}
	if err := tg.Send(t.Context(), Message{Title: "P2: nginx", Body: "<b>not markup</b>"}); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123456:abcdefghijklmnopqrstuvwxyz/sendMessage" || got["chat_id"] != "-1001" || got["parse_mode"] != nil || got["text"] != "P2: nginx\n\n<b>not markup</b>" {
		t.Errorf("request: %s %v", path, got)
	}
	tg.Token = "999:wrongwrongwrongwrongwrongwrong"
	if err := tg.Send(t.Context(), Message{Title: "x"}); err == nil || strings.Contains(err.Error(), "wrongwrong") {
		t.Errorf("token in error: %v", err)
	}
	if got := clip("ä"+strings.Repeat("a", 10), 5); got != "ä…" {
		t.Errorf("clip: %q", got)
	}
}
