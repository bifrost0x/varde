// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func lookupFrom(m map[string]string) LookupFunc {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.EnvSet = nil
	if !reflect.DeepEqual(cfg, Defaults()) {
		t.Fatalf("got %+v, want defaults %+v", cfg, Defaults())
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"VARDE_LISTEN_ADDR": "127.0.0.1:9000",
		"VARDE_LOG_LEVEL":   "DEBUG",
		"VARDE_LOG_FORMAT":  "text",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9000" || cfg.LogLevel != slog.LevelDebug || cfg.LogFormat != "text" || !cfg.DockerEnabled() {
		t.Fatalf("unexpected config %+v", cfg)
	}
}

func TestLoadBlankValueKeepsDefault(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{"VARDE_LISTEN_ADDR": "  "}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("got %q", cfg.ListenAddr)
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := Load(lookupFrom(map[string]string{
		"VARDE_LISTEN_ADDR": "nonsense",
		"VARDE_LOG_LEVEL":   "loud",
		"VARDE_LOG_FORMAT":  "xml",
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"VARDE_LISTEN_ADDR", "VARDE_LOG_LEVEL", "VARDE_LOG_FORMAT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestValidateListenAddrPort(t *testing.T) {
	for _, addr := range []string{":0", ":65536", ":http", "host"} {
		if err := validateListenAddr(addr); err == nil {
			t.Errorf("%q: expected error", addr)
		}
	}
	for _, addr := range []string{":1", "[::1]:8080", "0.0.0.0:65535"} {
		if err := validateListenAddr(addr); err != nil {
			t.Errorf("%q: %v", addr, err)
		}
	}
}

func TestDockerHost(t *testing.T) {
	cases := []struct {
		host, allow string
		ok          bool
	}{
		{"tcp://socket-proxy:2375", "", true},
		{"http://10.0.0.2:2375", "", true},
		{"off", "", true},
		{"unix:///var/run/docker.sock", "", false},
		{"unix:///var/run/docker.sock", "true", true},
		{"unix://", "true", false},
		{"tcp://", "", false},
		{"tcp://user:pw@proxy:2375", "", false},
		{"ssh://host", "", false},
		{"socket-proxy:2375", "", false},
	}
	for _, c := range cases {
		env := map[string]string{"VARDE_DOCKER_HOST": c.host}
		if c.allow != "" {
			env["VARDE_ALLOW_DIRECT_SOCKET"] = c.allow
		}
		_, err := Load(lookupFrom(env))
		if (err == nil) != c.ok {
			t.Errorf("%s (allow=%q): err=%v, want ok=%v", c.host, c.allow, err, c.ok)
		}
	}
}

func TestResyncInterval(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{"VARDE_RESYNC_INTERVAL": "30m"}))
	if err != nil || cfg.ResyncInterval != 30*time.Minute {
		t.Fatalf("got %v, %v", cfg.ResyncInterval, err)
	}
	for _, bad := range []string{"10s", "soon", "-1h"} {
		if _, err := Load(lookupFrom(map[string]string{"VARDE_RESYNC_INTERVAL": bad})); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestDataDirMustBeAbsolute(t *testing.T) {
	if _, err := Load(lookupFrom(map[string]string{"VARDE_DATA_DIR": "data"})); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestSecretFromValueAndFile(t *testing.T) {
	token := strings.Repeat("a", 40)
	cfg, err := Load(lookupFrom(map[string]string{"VARDE_API_TOKEN": token}))
	if err != nil || string(cfg.APIToken) != token {
		t.Fatalf("value: %v", err)
	}

	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(lookupFrom(map[string]string{"VARDE_API_TOKEN_FILE": path}))
	if err != nil || string(cfg.APIToken) != token {
		t.Fatalf("file: %v", err)
	}

	if _, err := Load(lookupFrom(map[string]string{"VARDE_API_TOKEN": token, "VARDE_API_TOKEN_FILE": path})); err == nil {
		t.Fatal("expected error when both are set")
	}
	if _, err := Load(lookupFrom(map[string]string{"VARDE_API_TOKEN": "short"})); err == nil {
		t.Fatal("expected error for short token")
	}
	if _, err := Load(lookupFrom(map[string]string{"VARDE_API_TOKEN_FILE": filepath.Join(t.TempDir(), "missing")})); err == nil {
		t.Fatal("expected error for missing file")
	}

	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, make([]byte, maxSecretFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(lookupFrom(map[string]string{"VARDE_API_TOKEN_FILE": big})); err == nil {
		t.Fatal("expected error for oversized file")
	}
}

func TestSecretRedaction(t *testing.T) {
	s := Secret("super-secret-value")
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %s %#v", s, s, s), fmt.Sprintf("%+v", Config{APIToken: s})} {
		if strings.Contains(out, "super-secret-value") {
			t.Errorf("secret leaked: %q", out)
		}
	}
}

// TestConfigurationDocInSync fails when an environment variable read by
// Load is not documented in docs/configuration.md.
func TestConfigurationDocInSync(t *testing.T) {
	var src []byte
	for _, f := range []string{"config.go", "agent.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src = append(src, b...)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`l\.(?:str|boolean|duration|secret|get|integer|list|domains)\("([A-Z_]+)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 5 {
		t.Fatalf("found only %d variables; pattern out of date?", len(matches))
	}
	for _, m := range matches {
		name := "`VARDE_" + m[1] + "`"
		if !strings.Contains(string(doc), name) {
			t.Errorf("%s is not documented in docs/configuration.md", name)
		}
	}
}

func TestNotifyAndExposureConfig(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"VARDE_PUBLIC_DOMAINS":   "Example.com, home.example.org.",
		"VARDE_INTERNAL_DOMAINS": "home.arpa,lan",
		"VARDE_BASE_URL":         "https://varde.example.com",
		"VARDE_NTFY_URL":         "http://ntfy.lan/varde",
		"VARDE_SMTP_HOST":        "mail.example.com",
		"VARDE_SMTP_FROM":        "Varde <varde@example.com>",
		"VARDE_SMTP_TO":          "ops@example.com, me@example.com",
		"VARDE_DIGEST_HOUR":      "7",
		"VARDE_DIGEST_WEEKDAY":   "Friday",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.PublicDomains, []string{"example.com", "home.example.org"}) || len(cfg.InternalDomains) != 2 {
		t.Errorf("domains: %v %v", cfg.PublicDomains, cfg.InternalDomains)
	}
	if !cfg.FromEnv("PUBLIC_DOMAINS") || cfg.FromEnv("SMTP_PORT") {
		t.Error("FromEnv")
	}
	n := cfg.Notify
	if n.SMTPPort != 587 || n.SMTPTLS != "starttls" || len(n.SMTPTo) != 2 || n.DigestHour != 7 || n.DigestWeekday != time.Friday {
		t.Errorf("notify: %+v", n)
	}
	bad := map[string]map[string]string{
		"domain url":       {"VARDE_PUBLIC_DOMAINS": "https://example.com"},
		"domain wildcard":  {"VARDE_PUBLIC_DOMAINS": "*.example.com"},
		"base url":         {"VARDE_BASE_URL": "varde.lan"},
		"base credentials": {"VARDE_BASE_URL": "https://u:p@varde.lan"},
		"ntfy no topic":    {"VARDE_NTFY_URL": "https://ntfy.example.com/"},
		"ntfy scheme":      {"VARDE_NTFY_URL": "ftp://ntfy.example.com/x"},
		"gotify no token":  {"VARDE_GOTIFY_URL": "https://gotify.lan"},
		"smtp no to":       {"VARDE_SMTP_HOST": "mail", "VARDE_SMTP_FROM": "a@b.c"},
		"smtp bad from":    {"VARDE_SMTP_HOST": "mail", "VARDE_SMTP_FROM": "nope", "VARDE_SMTP_TO": "a@b.c"},
		"smtp tls":         {"VARDE_SMTP_TLS": "ssl"},
		"smtp port":        {"VARDE_SMTP_PORT": "0"},
		"digest hour":      {"VARDE_DIGEST_HOUR": "24"},
		"digest weekday":   {"VARDE_DIGEST_WEEKDAY": "someday"},
		"cookie mode":      {"VARDE_COOKIE_SECURE": "maybe"},
		"trusted proxies":  {"VARDE_TRUSTED_PROXIES": "10.0.0.0/8,proxy.lan"},
		"discord http":     {"VARDE_DISCORD_WEBHOOK_URL": "http://discord.com/api/webhooks/1/x"},
		"discord not hook": {"VARDE_DISCORD_WEBHOOK_URL": "https://discord.com/channels/1"},
		"telegram no chat": {"VARDE_TELEGRAM_TOKEN": "123456:abcdefghijklmnopqrstuvwxyz"},
		"telegram token":   {"VARDE_TELEGRAM_TOKEN": "nope", "VARDE_TELEGRAM_CHAT_ID": "-1001"},
		"telegram no tok":  {"VARDE_TELEGRAM_CHAT_ID": "-1001"},
	}
	for name, env := range bad {
		if _, err := Load(lookupFrom(env)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The Discord URL is a secret: an error must not repeat it.
	if _, err := Load(lookupFrom(map[string]string{"VARDE_DISCORD_WEBHOOK_URL": "https://discord.com/x/s3cr3t"})); err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("discord error: %v", err)
	}
	c, err := Load(lookupFrom(map[string]string{"VARDE_DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/x", "VARDE_TELEGRAM_TOKEN": "123456:abcdefghijklmnopqrstuvwxyz", "VARDE_TELEGRAM_CHAT_ID": "@varde_alerts"}))
	if err != nil || c.Notify.DiscordWebhookURL == "" || c.Notify.TelegramChatID != "@varde_alerts" {
		t.Errorf("chat channels: %+v %v", c.Notify, err)
	}
}

func TestLocalHealthURL(t *testing.T) {
	cases := map[string]string{
		":8080":          "http://127.0.0.1:8080/healthz",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/healthz",
		"[::]:9000":      "http://127.0.0.1:9000/healthz",
		"[::1]:9000":     "http://[::1]:9000/healthz",
		"10.0.0.5:18080": "http://10.0.0.5:18080/healthz",
	}
	for addr, want := range cases {
		if got := (Config{ListenAddr: addr}).LocalHealthURL(); got != want {
			t.Errorf("%s: got %s, want %s", addr, got, want)
		}
	}
}

func TestModeSet(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || cfg.Mode != "direct" || cfg.ModeSet {
		t.Fatalf("unset: mode %q, set %v, err %v", cfg.Mode, cfg.ModeSet, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{"VARDE_MODE": "direct"}))
	if err != nil || cfg.Mode != "direct" || !cfg.ModeSet {
		t.Fatalf("explicit: mode %q, set %v, err %v", cfg.Mode, cfg.ModeSet, err)
	}
	// Feed mirrors without a mode prepare the uplink switch; they do not
	// change the mode.
	cfg, err = Load(lookupFrom(map[string]string{"VARDE_FEED_URLS": "https://feed.example.org"}))
	if err != nil || cfg.Mode != "direct" || cfg.ModeSet || len(cfg.FeedURLs) != 1 {
		t.Fatalf("mirrors only: %+v %v", cfg, err)
	}
}

func TestPackageURLs(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PackageURLs) != 1 || cfg.PackageURLs[0] != "https://raw.githubusercontent.com/bifrost0x/varde/data/feed" {
		t.Fatalf("default package mirrors: %v", cfg.PackageURLs)
	}
	if cfg.DirectQueries {
		t.Fatal("direct queries are on by default")
	}
	cfg, err = Load(lookupFrom(map[string]string{"VARDE_PACKAGE_URLS": ""}))
	if err != nil || len(cfg.PackageURLs) != 0 {
		t.Fatalf("empty value must switch the package off: %v, %v", cfg.PackageURLs, err)
	}
	cfg, err = Load(lookupFrom(map[string]string{"VARDE_PACKAGE_URLS": "file:///data/pkg.tar, https://mirror.example.org/feed", "VARDE_DIRECT_QUERIES": "true"}))
	if err != nil || len(cfg.PackageURLs) != 2 || !cfg.DirectQueries {
		t.Fatalf("explicit mirrors: %+v, %v", cfg.PackageURLs, err)
	}
	if _, err := Load(lookupFrom(map[string]string{"VARDE_PACKAGE_URLS": "http://x"})); err == nil {
		t.Fatal("http mirror accepted")
	}
}
