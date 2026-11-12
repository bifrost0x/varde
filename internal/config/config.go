// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates runtime configuration.
//
// Precedence is defaults < config file < environment. Only the environment
// layer exists so far; the file layer is added together with the settings
// that need it. Every secret can be given as NAME or NAME_FILE.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
)

// LookupFunc matches os.LookupEnv and allows tests to inject an environment.
type LookupFunc func(key string) (string, bool)

// DockerHostOff disables the local Docker collector.
const DockerHostOff = "off"

// maxSecretFileSize caps *_FILE reads; secrets are short tokens.
const maxSecretFileSize = 4 << 10

// DefaultPackageURL is where the project publishes the daily data package:
// the branch "data" of its repository.
const DefaultPackageURL = "https://raw.githubusercontent.com/bifrost0x/varde/data/feed"

// Config is the validated runtime configuration.
type Config struct {
	// ListenAddr is the UI/API listener address (host:port).
	ListenAddr string
	LogLevel   slog.Level
	LogFormat  string

	// DataDir holds the database and all other persistent state.
	DataDir string

	// Mode selects where advisories come from: direct, feed or hybrid.
	Mode string
	// ModeSet reports that VARDE_MODE is set in the environment. Without
	// it the uplink switch in the settings decides at runtime (ADR 0038).
	ModeSet bool
	// FeedURLs are the feed mirrors in order (https:// or file:// for
	// air-gapped imports); FeedRootFile is the initial trust root.
	FeedURLs       []string
	FeedRootFile   string
	FeedStaleAfter time.Duration
	// FeedAllowDevelopmentRoot accepts development roots (tests only).
	FeedAllowDevelopmentRoot bool
	// AgentListenAddr is the mTLS listener for agents, or "off".
	AgentListenAddr string
	// AgentBinaryDir holds the agent binaries (varde-linux-amd64,
	// varde-linux-arm64) the server installs and updates agents with. A
	// missing directory is not an error.
	AgentBinaryDir string
	// DockerHost is the Engine API endpoint, normally the socket proxy
	// (tcp://socket-proxy:2375), or DockerHostOff.
	DockerHost string
	// AllowDirectSocket permits a unix socket DockerHost and a mounted
	// /var/run/docker.sock. Insecure; see ADR 0006.
	AllowDirectSocket bool
	// ResyncInterval is the period of full inventory resyncs.
	ResyncInterval time.Duration

	// CatalogDir holds local catalog entries that extend or override the
	// built-in catalog. A missing directory is not an error.
	CatalogDir string

	// AdvisoryRefresh is the period of scheduled advisory refreshes.
	AdvisoryRefresh time.Duration
	// GitHubToken raises GitHub API rate limits; optional.
	GitHubToken Secret
	// DirectOSV and DirectNVD enable sources that reveal which packages or
	// products run to a third party; off by default.
	DirectOSV bool
	DirectNVD bool
	// PackageURLs are the mirrors of the data package, in order; empty
	// switches the package off.
	PackageURLs []string
	// DirectQueries lets Varde ask the public sources itself for apps the
	// data package does not cover; off by default. Without a data package
	// Varde always asks them.
	DirectQueries bool
	// NVDAPIKey raises NVD rate limits; optional.
	NVDAPIKey Secret
	// SNMPCommunity (v2c) or SNMPUser with SNMPAuth and SNMPPrivacy (v3,
	// SHA-256 and AES) let network scans read device descriptions.
	SNMPCommunity, SNMPAuth, SNMPPrivacy Secret
	SNMPUser                             string
	// EgressAllowlist, when set, restricts outbound HTTPS to these hosts.
	EgressAllowlist []string
	// HostAddresses are the addresses of the machine Varde runs on in the
	// network. In a container Varde sees only its own bridge addresses;
	// these tie "this host" to what the network scan finds and are the
	// address agents are told to use.
	HostAddresses []string
	// CABundleFile adds PEM certificates to the system trust store.
	CABundleFile string

	// PublicDomains and InternalDomains feed exposure detection.
	PublicDomains   []string
	InternalDomains []string
	// BaseURL is the externally reachable UI address, used for links in
	// notifications. Optional.
	BaseURL string

	Notify NotifyConfig

	// CookieSecure is auto, always or never (see auth.CookieMode).
	CookieSecure string
	// BehindTLSProxy marks a deployment behind a TLS-terminating proxy:
	// cookies become Secure and HSTS is sent.
	BehindTLSProxy bool
	// TrustedProxies may set X-Forwarded-For and X-Forwarded-Proto.
	TrustedProxies []string

	// EnvSet records which variables came from the environment.
	EnvSet map[string]bool

	// APIToken grants full API access until per-user tokens exist. Empty
	// disables the API.
	APIToken Secret
}

// NotifyConfig configures notification channels and digests.
type NotifyConfig struct {
	NtfyURL       string
	NtfyToken     Secret
	GotifyURL     string
	GotifyToken   Secret
	WebhookURL    string
	WebhookSecret Secret
	// DiscordWebhookURL holds its token in the path, so it is a secret.
	DiscordWebhookURL Secret
	TelegramToken     Secret
	TelegramChatID    string

	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword Secret
	SMTPFrom     string
	SMTPTo       []string
	SMTPTLS      string

	DigestHour    int
	DigestWeekday time.Weekday
}

// Secret is a string that never prints its value.
type Secret string

// String implements fmt.Stringer with redaction.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

// GoString implements fmt.GoStringer with redaction.
func (s Secret) GoString() string { return s.String() }

// LogValue implements slog.LogValuer with redaction.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// Defaults returns the built-in default configuration.
func Defaults() Config {
	return Config{
		ListenAddr:      ":8080",
		LogLevel:        slog.LevelInfo,
		LogFormat:       "json",
		DataDir:         "/data",
		DockerHost:      "tcp://socket-proxy:2375",
		AgentListenAddr: ":8443",
		AgentBinaryDir:  "/usr/lib/varde/agent",
		Mode:            "direct",
		PackageURLs:     []string{DefaultPackageURL},
		FeedStaleAfter:  72 * time.Hour,
		ResyncInterval:  6 * time.Hour,
		CatalogDir:      "/catalog.d",
		AdvisoryRefresh: 6 * time.Hour,
		CookieSecure:    "auto",
		Notify: NotifyConfig{
			SMTPPort:      587,
			SMTPTLS:       "starttls",
			DigestHour:    8,
			DigestWeekday: time.Monday,
		},
	}
}

// Load builds the configuration from defaults and the environment and
// validates it. All problems are reported at once.
func Load(lookup LookupFunc) (Config, error) {
	l := loader{lookup: lookup, set: map[string]bool{}}
	cfg := Defaults()

	l.str("LISTEN_ADDR", &cfg.ListenAddr)
	if err := validateListenAddr(cfg.ListenAddr); err != nil {
		l.fail("LISTEN_ADDR", err)
	}

	if v, ok := l.get("LOG_LEVEL"); ok {
		lvl, err := parseLevel(v)
		if err != nil {
			l.fail("LOG_LEVEL", err)
		}
		cfg.LogLevel = lvl
	}

	if v, ok := l.get("LOG_FORMAT"); ok {
		switch v {
		case "json", "text":
			cfg.LogFormat = v
		default:
			l.fail("LOG_FORMAT", fmt.Errorf("must be json or text, got %q", v))
		}
	}

	l.str("DATA_DIR", &cfg.DataDir)
	if !filepath.IsAbs(cfg.DataDir) {
		l.fail("DATA_DIR", fmt.Errorf("must be an absolute path, got %q", cfg.DataDir))
	}

	l.str("DOCKER_HOST", &cfg.DockerHost)
	l.boolean("ALLOW_DIRECT_SOCKET", &cfg.AllowDirectSocket)
	if err := validateDockerHost(cfg.DockerHost, cfg.AllowDirectSocket); err != nil {
		l.fail("DOCKER_HOST", err)
	}

	l.duration("RESYNC_INTERVAL", &cfg.ResyncInterval, time.Minute)

	l.str("MODE", &cfg.Mode)
	cfg.ModeSet = l.set["MODE"]
	switch cfg.Mode {
	case "direct", "feed", "hybrid":
	default:
		l.fail("MODE", fmt.Errorf("must be direct, feed or hybrid, got %q", cfg.Mode))
	}
	cfg.FeedURLs = l.list("FEED_URLS")
	for _, u := range cfg.FeedURLs {
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "file:///") {
			l.fail("FEED_URLS", fmt.Errorf("%q: use https:// or file:///", u))
		}
	}
	if cfg.Mode != "direct" && len(cfg.FeedURLs) == 0 {
		l.fail("FEED_URLS", fmt.Errorf("required in %s mode", cfg.Mode))
	}
	if _, ok := l.lookup(buildinfo.EnvPrefix + "PACKAGE_URLS"); ok {
		// Set but empty switches the package off.
		cfg.PackageURLs = l.list("PACKAGE_URLS")
	}
	for _, u := range cfg.PackageURLs {
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "file:///") {
			l.fail("PACKAGE_URLS", fmt.Errorf("%q: use https:// or file:///", u))
		}
	}
	l.boolean("DIRECT_QUERIES", &cfg.DirectQueries)
	l.str("FEED_ROOT_FILE", &cfg.FeedRootFile)
	if cfg.FeedRootFile != "" && !filepath.IsAbs(cfg.FeedRootFile) {
		l.fail("FEED_ROOT_FILE", fmt.Errorf("must be an absolute path, got %q", cfg.FeedRootFile))
	}
	l.duration("FEED_STALE_AFTER", &cfg.FeedStaleAfter, time.Hour)
	l.boolean("FEED_ALLOW_DEVELOPMENT_ROOT", &cfg.FeedAllowDevelopmentRoot)

	l.str("AGENT_LISTEN_ADDR", &cfg.AgentListenAddr)
	if cfg.AgentListenAddr != "off" {
		if err := validateListenAddr(cfg.AgentListenAddr); err != nil {
			l.fail("AGENT_LISTEN_ADDR", err)
		}
	}

	l.str("AGENT_BINARY_DIR", &cfg.AgentBinaryDir)
	if !filepath.IsAbs(cfg.AgentBinaryDir) {
		l.fail("AGENT_BINARY_DIR", fmt.Errorf("must be an absolute path, got %q", cfg.AgentBinaryDir))
	}

	l.str("CATALOG_DIR", &cfg.CatalogDir)
	if !filepath.IsAbs(cfg.CatalogDir) {
		l.fail("CATALOG_DIR", fmt.Errorf("must be an absolute path, got %q", cfg.CatalogDir))
	}

	l.duration("ADVISORY_REFRESH", &cfg.AdvisoryRefresh, time.Hour)
	l.secret("GITHUB_TOKEN", &cfg.GitHubToken)
	l.boolean("DIRECT_OSV", &cfg.DirectOSV)
	l.boolean("DIRECT_NVD", &cfg.DirectNVD)
	l.secret("NVD_API_KEY", &cfg.NVDAPIKey)
	l.secret("SNMP_COMMUNITY", &cfg.SNMPCommunity)
	l.str("SNMP_USER", &cfg.SNMPUser)
	l.secret("SNMP_AUTH", &cfg.SNMPAuth)
	l.secret("SNMP_PRIVACY", &cfg.SNMPPrivacy)
	if cfg.SNMPUser != "" && cfg.SNMPAuth == "" {
		l.fail("SNMP_AUTH", errors.New("SNMP v3 needs an authentication passphrase with VARDE_SNMP_USER"))
	}
	if v, ok := l.get("EGRESS_ALLOWLIST"); ok {
		for _, h := range strings.Split(v, ",") {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if strings.ContainsAny(h, "/:@ ") {
				l.fail("EGRESS_ALLOWLIST", fmt.Errorf("%q must be a host name, not a URL", h))
				continue
			}
			cfg.EgressAllowlist = append(cfg.EgressAllowlist, h)
		}
	}
	if v, ok := l.get("HOST_ADDRESS"); ok {
		for _, a := range strings.Split(v, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			ip, err := netip.ParseAddr(a)
			if err != nil {
				l.fail("HOST_ADDRESS", fmt.Errorf("%q is not an IP address", a))
				continue
			}
			cfg.HostAddresses = append(cfg.HostAddresses, ip.Unmap().String())
		}
	}
	l.str("CA_BUNDLE_FILE", &cfg.CABundleFile)
	if cfg.CABundleFile != "" && !filepath.IsAbs(cfg.CABundleFile) {
		l.fail("CA_BUNDLE_FILE", fmt.Errorf("must be an absolute path, got %q", cfg.CABundleFile))
	}

	cfg.PublicDomains = l.domains("PUBLIC_DOMAINS")
	cfg.InternalDomains = l.domains("INTERNAL_DOMAINS")
	l.str("BASE_URL", &cfg.BaseURL)
	if cfg.BaseURL != "" {
		l.httpURL("BASE_URL", cfg.BaseURL)
	}
	l.notify(&cfg.Notify)

	l.str("COOKIE_SECURE", &cfg.CookieSecure)
	switch cfg.CookieSecure {
	case "auto", "always", "never":
	default:
		l.fail("COOKIE_SECURE", fmt.Errorf("must be auto, always or never, got %q", cfg.CookieSecure))
	}
	l.boolean("BEHIND_TLS_PROXY", &cfg.BehindTLSProxy)
	cfg.TrustedProxies = l.list("TRUSTED_PROXIES")
	for _, p := range cfg.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				l.fail("TRUSTED_PROXIES", fmt.Errorf("%q is not an IP address or CIDR", p))
			}
		}
	}

	l.secret("API_TOKEN", &cfg.APIToken)
	if cfg.APIToken != "" && len(cfg.APIToken) < 32 {
		l.fail("API_TOKEN", errors.New("must be at least 32 characters"))
	}

	if len(l.errs) > 0 {
		return Config{}, errors.Join(l.errs...)
	}
	cfg.EnvSet = l.set
	return cfg, nil
}

// FromEnv reports whether the variable NAME (without prefix) was set in the
// environment; such settings are locked in the UI.
func (c Config) FromEnv(name string) bool { return c.EnvSet[name] }

// LocalHealthURL returns the URL the healthcheck subcommand probes. A
// wildcard or empty listen host is mapped to loopback.
func (c Config) LocalHealthURL() string {
	host, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		// Load guarantees a valid address; fall back to the default port.
		port = "8080"
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

// DockerEnabled reports whether the local Docker collector runs.
func (c Config) DockerEnabled() bool { return c.DockerHost != DockerHostOff }

type loader struct {
	lookup LookupFunc
	errs   []error
	set    map[string]bool
}

func (l *loader) fail(name string, err error) {
	l.errs = append(l.errs, fmt.Errorf("%s%s: %w", buildinfo.EnvPrefix, name, err))
}

func (l *loader) get(name string) (string, bool) {
	v, ok := l.lookup(buildinfo.EnvPrefix + name)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v != "" {
		l.set[name] = true
	}
	return v, v != ""
}

func (l *loader) str(name string, dst *string) {
	if v, ok := l.get(name); ok {
		*dst = v
	}
}

func (l *loader) boolean(name string, dst *bool) {
	v, ok := l.get(name)
	if !ok {
		return
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.fail(name, fmt.Errorf("must be true or false, got %q", v))
		return
	}
	*dst = b
}

func (l *loader) duration(name string, dst *time.Duration, minimum time.Duration) {
	v, ok := l.get(name)
	if !ok {
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.fail(name, fmt.Errorf("invalid duration %q", v))
		return
	}
	if d < minimum {
		l.fail(name, fmt.Errorf("must be at least %s, got %s", minimum, d))
		return
	}
	*dst = d
}

func (l *loader) integer(name string, dst *int, lo, hi int) {
	v, ok := l.get(name)
	if !ok {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		l.fail(name, fmt.Errorf("must be an integer between %d and %d, got %q", lo, hi, v))
		return
	}
	*dst = n
}

func (l *loader) list(name string) []string {
	v, ok := l.get(name)
	if !ok {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (l *loader) domains(name string) []string {
	var out []string
	for _, d := range l.list(name) {
		d = strings.Trim(strings.ToLower(d), ".")
		if strings.ContainsAny(d, "/:@ *") || !strings.Contains(d, ".") && d != "lan" && d != "local" && d != "internal" && d != "home" {
			l.fail(name, fmt.Errorf("%q is not a domain suffix (e.g. example.com)", d))
			continue
		}
		out = append(out, d)
	}
	return out
}

// httpURL validates an absolute http(s) URL without credentials.
func (l *loader) httpURL(name, raw string) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		l.fail(name, fmt.Errorf("must be an absolute http(s) URL without credentials, got %q", raw))
	}
}

func (l *loader) notify(n *NotifyConfig) {
	l.str("NTFY_URL", &n.NtfyURL)
	l.secret("NTFY_TOKEN", &n.NtfyToken)
	if n.NtfyURL != "" {
		l.httpURL("NTFY_URL", n.NtfyURL)
		if u, err := url.Parse(n.NtfyURL); err == nil {
			if topic := strings.Trim(u.Path, "/"); topic == "" || strings.Contains(topic, "/") {
				l.fail("NTFY_URL", errors.New("must end with the topic, e.g. https://ntfy.example.com/varde"))
			}
		}
	}
	l.str("GOTIFY_URL", &n.GotifyURL)
	l.secret("GOTIFY_TOKEN", &n.GotifyToken)
	if n.GotifyURL != "" {
		l.httpURL("GOTIFY_URL", n.GotifyURL)
		if n.GotifyToken == "" {
			l.fail("GOTIFY_TOKEN", errors.New("required when GOTIFY_URL is set"))
		}
	}
	l.str("WEBHOOK_URL", &n.WebhookURL)
	l.secret("WEBHOOK_SECRET", &n.WebhookSecret)
	if n.WebhookURL != "" {
		l.httpURL("WEBHOOK_URL", n.WebhookURL)
	}
	l.secret("DISCORD_WEBHOOK_URL", &n.DiscordWebhookURL)
	if n.DiscordWebhookURL != "" {
		if u, err := url.Parse(string(n.DiscordWebhookURL)); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !strings.Contains(u.Path, "/webhooks/") {
			// The value is a secret; it is not repeated in the error.
			l.fail("DISCORD_WEBHOOK_URL", errors.New("must be a Discord webhook URL (https://discord.com/api/webhooks/...)"))
		}
	}
	l.secret("TELEGRAM_TOKEN", &n.TelegramToken)
	l.str("TELEGRAM_CHAT_ID", &n.TelegramChatID)
	if n.TelegramToken != "" || n.TelegramChatID != "" {
		if !telegramToken.MatchString(string(n.TelegramToken)) {
			l.fail("TELEGRAM_TOKEN", errors.New("must be a bot token from BotFather (<digits>:<letters>)"))
		}
		if !telegramChat.MatchString(n.TelegramChatID) {
			l.fail("TELEGRAM_CHAT_ID", fmt.Errorf("must be a numeric chat ID or @channelname, got %q", n.TelegramChatID))
		}
	}

	l.str("SMTP_HOST", &n.SMTPHost)
	l.integer("SMTP_PORT", &n.SMTPPort, 1, 65535)
	l.str("SMTP_USERNAME", &n.SMTPUsername)
	l.secret("SMTP_PASSWORD", &n.SMTPPassword)
	l.str("SMTP_FROM", &n.SMTPFrom)
	n.SMTPTo = l.list("SMTP_TO")
	l.str("SMTP_TLS", &n.SMTPTLS)
	switch n.SMTPTLS {
	case "starttls", "tls", "none":
	default:
		l.fail("SMTP_TLS", fmt.Errorf("must be starttls, tls or none, got %q", n.SMTPTLS))
	}
	if n.SMTPHost != "" {
		if _, err := mail.ParseAddress(n.SMTPFrom); err != nil {
			l.fail("SMTP_FROM", fmt.Errorf("invalid address %q", n.SMTPFrom))
		}
		if len(n.SMTPTo) == 0 {
			l.fail("SMTP_TO", errors.New("at least one recipient is required when SMTP_HOST is set"))
		}
		for _, to := range n.SMTPTo {
			if _, err := mail.ParseAddress(to); err != nil {
				l.fail("SMTP_TO", fmt.Errorf("invalid address %q", to))
			}
		}
	}

	l.integer("DIGEST_HOUR", &n.DigestHour, 0, 23)
	if v, ok := l.get("DIGEST_WEEKDAY"); ok {
		found := false
		for d := time.Sunday; d <= time.Saturday; d++ {
			if strings.EqualFold(v, d.String()) {
				n.DigestWeekday, found = d, true
			}
		}
		if !found {
			l.fail("DIGEST_WEEKDAY", fmt.Errorf("must be a weekday name such as monday, got %q", v))
		}
	}
}

// secret reads NAME or NAME_FILE; setting both is an error so that a stale
// value cannot silently win.
func (l *loader) secret(name string, dst *Secret) {
	v, hasValue := l.get(name)
	path, hasFile := l.get(name + "_FILE")
	switch {
	case hasValue && hasFile:
		l.fail(name, fmt.Errorf("set either %s%s or %s%s_FILE, not both", buildinfo.EnvPrefix, name, buildinfo.EnvPrefix, name))
	case hasValue:
		*dst = Secret(v)
	case hasFile:
		s, err := readSecretFile(path)
		if err != nil {
			l.fail(name+"_FILE", err)
			return
		}
		*dst = Secret(s)
	}
}

func readSecretFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the operator's own configuration
	if err != nil {
		return "", fmt.Errorf("open secret file: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	if len(b) > maxSecretFileSize {
		return "", fmt.Errorf("secret file larger than %d bytes", maxSecretFileSize)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("secret file is empty")
	}
	return s, nil
}

func validateListenAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

func validateDockerHost(host string, allowDirect bool) error {
	if host == DockerHostOff {
		return nil
	}
	u, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", host, err)
	}
	switch u.Scheme {
	case "tcp", "http", "https":
		if u.Host == "" {
			return fmt.Errorf("missing host in %q", host)
		}
		if u.User != nil {
			return errors.New("credentials in the URL are not supported")
		}
		return nil
	case "unix":
		if !allowDirect {
			return fmt.Errorf("unix socket %q gives root-equivalent access; use a socket proxy, or set %sALLOW_DIRECT_SOCKET=true to accept the risk", host, buildinfo.EnvPrefix)
		}
		if u.Path == "" {
			return fmt.Errorf("missing socket path in %q", host)
		}
		return nil
	default:
		return fmt.Errorf("unsupported scheme %q (tcp, http, https, unix or %q)", u.Scheme, DockerHostOff)
	}
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("must be debug, info, warn or error, got %q", s)
	}
}

var (
	telegramToken = regexp.MustCompile(`^\d{1,20}:[A-Za-z0-9_-]{20,100}$`)
	telegramChat  = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)
