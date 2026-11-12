// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/varde/internal/auth"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

// installTokenLifetime is how long the token of a push installation stays
// valid: the agent enrolls seconds after the installation.
const installTokenLifetime = 15 * time.Minute

// agentInstallData drives the install page: hosts, host key confirmation
// with the credentials, result per host. One page installs on one host or
// on several with the same credentials.
type agentInstallData struct {
	Step, Error           string
	Port, User, ServerURL string
	// LoopbackURL is set when the suggested address is this machine
	// itself, which the hosts cannot reach.
	LoopbackURL bool
	Docker      bool
	Platforms   []string
	Unavailable string
	Hosts       []installHost
	// Addresses is the host list as entered, one per line.
	Addresses string
}

// installHost is one host of an installation: its confirmed key, then the
// outcome.
type installHost struct {
	Address            string
	HostKeyFingerprint string
	HostKeyFile        string
	// Error is why the key could not be read or the installation failed.
	Error  string
	Result *integrations.AgentInstallResult
	// Enrolled is set when the new agent used its token.
	Enrolled bool
	key      ssh.PublicKey
	tokenID  string
}

// Done reports whether the installation succeeded.
func (h installHost) Done() bool { return h.Result != nil && h.Error == "" }

// agentInstallReady reports whether Varde can install agents itself.
func (a *app) agentInstallReady() bool {
	return a.d.AgentCAPin != "" && a.d.Network != nil && len(a.d.AgentBinaries.Available()) > 0
}

func (a *app) agentInstallForm(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	var addrs []string
	for _, v := range r.URL.Query()["address"] {
		if _, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil && len(addrs) < maxBulkInstall {
			addrs = append(addrs, strings.TrimSpace(v))
		}
	}
	a.renderAgentInstall(w, r, cur, http.StatusOK, agentInstallData{Step: "address", Addresses: strings.Join(addrs, "\n"), Port: "22", User: "root",
		ServerURL: a.defaultAgentURL(r), Docker: true})
}

func (a *app) renderAgentInstall(w http.ResponseWriter, r *http.Request, cur *auth.Current, status int, d agentInstallData) {
	switch {
	case a.d.AgentCAPin == "":
		d.Unavailable = "The agent listener is switched off (VARDE_AGENT_LISTEN_ADDR=off)."
	case a.d.Network == nil:
		d.Unavailable = "Network discovery is not configured."
	case len(a.d.AgentBinaries.Available()) == 0:
		d.Unavailable = "This Varde server ships no agent binaries (VARDE_AGENT_BINARY_DIR). The container image contains them; for a binary installation, put varde-linux-amd64 and varde-linux-arm64 from the release there."
	}
	d.Platforms = a.d.AgentBinaries.Available()
	// The page carries the confirmed host key and, on errors, never the
	// credentials; keep it out of caches anyway.
	w.Header().Set("Cache-Control", "no-store")
	a.page(w, r, cur, status, "agentinstall", view{Title: "Install the agent", Nav: "connections", Tabs: tabs("connections", "/connections/agents"), Data: d})
}

// defaultAgentURL guesses the agent listener as hosts reach it: this
// machine's configured address, else the host name the browser used, with
// the listener's port. The configured address comes first: the browser's
// name is often that of a reverse proxy, which forwards the web interface
// and not the agent port.
func (a *app) defaultAgentURL(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if len(a.d.HostAddresses) > 0 {
		host = a.d.HostAddresses[0]
	}
	port := "8443"
	if _, p, err := net.SplitHostPort(a.d.AgentListenAddr); err == nil && p != "" {
		port = p
	}
	if host == "" {
		return ""
	}
	return "https://" + net.JoinHostPort(strings.Trim(host, "[]"), port)
}

// loopbackURL reports whether a server URL names the local machine: the
// browser's address when Varde is opened on the machine it runs on.
func loopbackURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// validAgentURL accepts what the agent's VARDE_SERVER_URL accepts.
func validAgentURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") &&
		u.RawQuery == "" && u.Fragment == "" && !strings.ContainsAny(s, " \t\r\n\"'\\$`")
}

// installParallel bounds the hosts read or installed at the same time.
const installParallel = 4

func (a *app) agentInstall(w http.ResponseWriter, r *http.Request, cur *auth.Current) {
	ctx := r.Context()
	d := agentInstallData{Step: "address", Addresses: strings.TrimSpace(r.PostFormValue("addresses")),
		Port: strings.TrimSpace(r.PostFormValue("port")), User: strings.TrimSpace(r.PostFormValue("user")),
		ServerURL: strings.TrimSpace(r.PostFormValue("server_url")), Docker: r.PostFormValue("docker") == "yes"}
	if r.PostFormValue("step") == "address" {
		d.Docker = true
	}
	fail := func(msg string) {
		d.Error = msg
		a.renderAgentInstall(w, r, cur, http.StatusBadRequest, d)
	}
	if !a.agentInstallReady() {
		a.renderAgentInstall(w, r, cur, http.StatusConflict, d)
		return
	}
	port, err := strconv.Atoi(d.Port)
	if err != nil {
		port = 0
	}
	addrs := strings.FieldsFunc(d.Addresses, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })
	if len(addrs) == 0 {
		fail("Enter the address of at least one host.")
		return
	}
	if len(addrs) > maxBulkInstall {
		fail("At most " + strconv.Itoa(maxBulkInstall) + " hosts at once.")
		return
	}
	cfgs := make([]integrations.DockerSSHConfig, len(addrs))
	for i, addr := range addrs {
		cfgs[i] = integrations.DockerSSHConfig{Address: addr, Port: port, User: d.User}
		if _, err := netip.ParseAddr(addr); err != nil && !hostName.MatchString(addr) {
			fail("Enter IP addresses or host names, one per line; " + strconv.Quote(truncateRunes(addr, 40)) + " is neither.")
			return
		}
		if err := cfgs[i].Validate(); err != nil {
			fail(addr + ": " + err.Error())
			return
		}
	}
	d.Addresses = strings.Join(addrs, "\n")
	// Installing on several hosts takes longer than the server's write
	// timeout allows.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Minute))
	d.Hosts = make([]installHost, len(addrs))
	each(len(addrs), func(i int) {
		h := installHost{Address: addrs[i]}
		key, err := integrations.FetchHostKey(ctx, cfgs[i].Target(), a.d.Network.Dial())
		if err != nil {
			h.Error = scopeHint(err)
		} else {
			h.key, h.HostKeyFingerprint, h.HostKeyFile = key, integrations.Fingerprint(key), integrations.KeyFile(key)
		}
		d.Hosts[i] = h
	})
	d.Step = "credentials"
	if r.PostFormValue("step") == "address" {
		if d.ServerURL == "" {
			d.ServerURL = a.defaultAgentURL(r)
			d.LoopbackURL = loopbackURL(d.ServerURL)
		}
		a.renderAgentInstall(w, r, cur, http.StatusOK, d)
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		fail("Compare the host key fingerprints and confirm them.")
		return
	}
	if !validAgentURL(d.ServerURL) {
		fail("Enter the address the hosts reach this Varde server's agent port at, as https://host:port.")
		return
	}
	if loopbackURL(d.ServerURL) {
		fail("The address points at the host itself (localhost); other hosts cannot reach Varde there. Enter this server's name or address in your network.")
		return
	}
	password := r.PostFormValue("password")
	privateKey := strings.TrimSpace(r.PostFormValue("private_key"))
	if len(password) > 1024 || strings.ContainsAny(password, "\r\n\x00") || len(privateKey) > 16<<10 || len(r.PostFormValue("passphrase")) > 1024 {
		fail("The password, key or passphrase is too long or contains line breaks.")
		return
	}
	if password == "" && privateKey == "" {
		fail("Enter the password or paste a private key for " + d.User + ".")
		return
	}
	// Only hosts the user selected, each with the key read again: it must
	// match the fingerprint the user confirmed.
	selected := map[string]bool{}
	for _, v := range r.PostForm["host"] {
		selected[v] = true
	}
	ready := 0
	for i := range d.Hosts {
		h := &d.Hosts[i]
		switch {
		case h.key == nil:
		case !selected[h.Address]:
			h.Error = "Not selected."
		case r.PostFormValue("fp-"+h.Address) != h.HostKeyFingerprint:
			h.Error = "The host key changed while you were setting up. Compare the new fingerprint and start again."
		default:
			ready++
		}
	}
	if ready == 0 {
		fail("Select at least one host whose key you compared.")
		return
	}
	// The agents this server knows: an identity found on a host that is
	// not among them is from another server or revoked, and is replaced.
	known := []string{}
	all, err := a.d.Store.Hosts(ctx)
	if err != nil {
		a.fail(w, r, cur, err)
		return
	}
	for _, h := range all {
		if h.Source == inventory.SourceAgent && h.State != inventory.HostRevoked {
			known = append(known, h.ID)
		}
	}
	each(len(d.Hosts), func(i int) {
		h := &d.Hosts[i]
		if h.Error != "" || h.key == nil {
			return
		}
		target := cfgs[i].Target()
		token, tokenID, err := a.installToken(ctx, cur, target)
		if err != nil {
			h.Error = "Could not create an enrollment token."
			return
		}
		res, err := integrations.InstallAgent(ctx, integrations.AgentInstall{
			Target: target, HostKey: h.key, User: d.User,
			Password: password, PrivateKey: []byte(privateKey), Passphrase: r.PostFormValue("passphrase"),
			Docker: d.Docker, ServerURL: d.ServerURL, Token: token, KnownAgents: known,
			Binary: func(p string) (string, bool) {
				b, ok := a.d.AgentBinaries.For(p)
				return b.Path, ok
			},
		}, a.d.Network.Dial())
		h.Result = &res
		if err != nil {
			// The token is useless now; nothing else was created on the host.
			_ = a.d.Store.DeleteEnrollmentToken(context.WithoutCancel(ctx), tokenID)
			a.audit(r, cur, "agent.install.failed", tokenID, d.User+"@"+target)
			h.Error = scopeHint(err)
			if errors.Is(err, integrations.ErrHostKeyChanged) {
				h.Error = "The host key changed while you were setting up. Start again."
			}
			return
		}
		a.audit(r, cur, "agent.install", tokenID, d.User+"@"+target+", "+res.Platform+", "+res.Init)
		if res.KeptEnrollment {
			// The agent reports under its existing identity.
			_ = a.d.Store.DeleteEnrollmentToken(ctx, tokenID)
			h.Enrolled = true
			return
		}
		if res.Unreachable != "" {
			// It cannot enroll until the way is open; no point waiting. The
			// token stays valid for its lifetime, so opening the way soon
			// is enough: the agent keeps trying.
			return
		}
		h.tokenID = tokenID
	})
	// The new agents enroll within seconds; wait for all of them together.
	deadline := time.Now().Add(20 * time.Second)
	for i := range d.Hosts {
		if h := &d.Hosts[i]; h.tokenID != "" {
			h.Enrolled = a.waitEnrolled(ctx, h.tokenID, time.Until(deadline))
		}
	}
	d.Step = "done"
	a.renderAgentInstall(w, r, cur, http.StatusOK, d)
}

// each runs fn for 0..n-1, at most installParallel at a time.
func each(n int, fn func(i int)) {
	sem := make(chan struct{}, installParallel)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}()
	}
	wg.Wait()
}

// installToken creates the one-time enrollment token for one installation.
func (a *app) installToken(ctx context.Context, cur *auth.Current, target string) (token, id string, err error) {
	secret, err := auth.RandomToken(32)
	if err != nil {
		return "", "", err
	}
	if id, err = auth.RandomToken(12); err != nil {
		return "", "", err
	}
	now := a.d.Now()
	name := "install on " + target
	if err := a.d.Store.CreateEnrollmentToken(ctx, store.EnrollmentToken{
		ID: id, Name: name, TokenHash: auth.HashToken(secret), CreatedBy: cur.User.Username,
		CreatedAt: now, ExpiresAt: now.Add(installTokenLifetime),
	}); err != nil {
		return "", "", err
	}
	return wire.FormatToken(secret, a.d.AgentCAPin), id, nil
}

// waitEnrolled waits until the token was used, that is, the new agent
// enrolled, or the wait is over.
func (a *app) waitEnrolled(ctx context.Context, tokenID string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		pending, err := a.d.Store.PendingEnrollmentTokens(ctx, a.d.Now())
		if err != nil {
			return false
		}
		if !slices.ContainsFunc(pending, func(t store.EnrollmentToken) bool { return t.ID == tokenID }) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
}

var hostName = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
