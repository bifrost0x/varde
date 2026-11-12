// SPDX-License-Identifier: Apache-2.0

package fleet_test

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/agent"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/fleet"
	"github.com/bifrost0x/varde/internal/fleet/wire"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

type inventoryLog struct {
	mu   sync.Mutex
	got  []string
	fail error
}

func (l *inventoryLog) store(_ context.Context, _ string, raw []byte, _ time.Time) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail != nil {
		return false, l.fail
	}
	l.got = append(l.got, string(raw))
	return true, nil
}

func (l *inventoryLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.got)
}

// The agent sends the host inventory with every full snapshot; heartbeats
// carry none, and a changed inventory makes the next report a full one.
func TestHostInventoryTravelsWithSnapshots(t *testing.T) {
	e := newEnv(t)
	var log inventoryLog
	e.fleet.Inventory = log.store
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	inv := "varde-inventory 2\n@@end\n"
	reads := 0
	a.ReadInventory = func(context.Context) ([]byte, error) {
		reads++
		return []byte(inv), nil
	}
	now := time.Now()
	apply := func(at time.Time) {
		t.Helper()
		if _, err := a.ApplySnapshot(t.Context(), "", "container", nil, at); err != nil {
			t.Fatal(err)
		}
	}
	apply(now)
	if log.count() != 1 || log.got[0] != inv {
		t.Fatalf("first report: %q", log.got)
	}
	// Within half the interval the inventory is not read again, and an
	// unchanged snapshot is only a heartbeat.
	apply(now.Add(time.Minute))
	if reads != 1 || log.count() != 1 {
		t.Fatalf("reads %d, stored %d", reads, log.count())
	}
	inv = "varde-inventory 2\n@@hostname\nweb2\n@@end\n"
	apply(now.Add(10 * time.Minute))
	if reads != 2 || log.count() != 2 || log.got[1] != inv {
		t.Fatalf("changed inventory: reads %d, stored %q", reads, log.got)
	}

	// An inventory the server cannot read is refused, not ignored.
	log.mu.Lock()
	log.fail = wire.ErrBadInventory
	log.mu.Unlock()
	inv = "something else"
	if _, err := a.ApplySnapshot(t.Context(), "", "container", nil, now.Add(20*time.Minute)); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("bad inventory: %v", err)
	}
}

// A failing inventory read sends the containers without it; the server
// keeps the last inventory.
func TestHostInventoryReadFailure(t *testing.T) {
	e := newEnv(t)
	var log inventoryLog
	e.fleet.Inventory = log.store
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	a.ReadInventory = func(context.Context) ([]byte, error) { return nil, errors.New("no /bin/sh") }
	if err := push(t, a, container("c1", "immich", "ghcr.io/immich-app/immich-server:v1.120.0")); err != nil {
		t.Fatal(err)
	}
	if log.count() != 0 {
		t.Fatalf("stored %q", log.got)
	}
}

// fakeBinary is a shell script that answers "version" like varde does.
func fakeBinary(t *testing.T, path, tag string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho varde "+tag+"\n"), 0o750); err != nil { //nolint:gosec // test executable
		t.Fatal(err)
	}
}

func updateEnv(t *testing.T) (*env, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("self-update replaces Linux binaries")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	e := newEnv(t)
	dir := t.TempDir()
	served := filepath.Join(dir, fleet.BinaryName(agent.Platform()))
	fakeBinary(t, served, "new")
	b, err := fleet.LoadBinaries(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.fleet.Binaries = b
	return e, served
}

func TestSelfUpdate(t *testing.T) {
	e, served := updateEnv(t)
	exe := filepath.Join(t.TempDir(), "varde")
	fakeBinary(t, exe, "old")
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	if err := a.EnableSelfUpdate(exe); err != nil {
		t.Fatal(err)
	}
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(exe)
	want, _ := os.ReadFile(served)
	if string(got) != string(want) || !a.Updated() {
		t.Fatalf("binary not replaced: %q, updated %v", got, a.Updated())
	}
	// Running the offered binary already, the agent does nothing.
	b := e.agent(t, e.token(t, time.Hour), t.TempDir())
	if err := b.EnableSelfUpdate(exe); err != nil {
		t.Fatal(err)
	}
	if err := push(t, b); err != nil || b.Updated() {
		t.Fatalf("same binary: err %v, updated %v", err, b.Updated())
	}
}

// A binary that does not match the checksum of the report answer, or does
// not run, never replaces the running one.
func TestSelfUpdateRefusesBadBinaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"checksum mismatch", "#!/bin/sh\necho varde tampered\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, served := updateEnv(t)
			// Changed after the server hashed it: the download no longer
			// matches what the report announced.
			if err := os.WriteFile(served, []byte(tc.content), 0o750); err != nil { //nolint:gosec // test executable
				t.Fatal(err)
			}
			exe := filepath.Join(t.TempDir(), "varde")
			fakeBinary(t, exe, "old")
			a := e.agent(t, e.token(t, time.Hour), t.TempDir())
			if err := a.EnableSelfUpdate(exe); err != nil {
				t.Fatal(err)
			}
			if err := push(t, a); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(exe); !strings.Contains(string(got), "old") || a.Updated() {
				t.Fatalf("replaced by a bad binary: %q", got)
			}
		})
	}
	t.Run("does not run", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("Linux only")
		}
		e := newEnv(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, fleet.BinaryName(agent.Platform())), []byte("#!/bin/sh\nexit 1\n"), 0o750); err != nil { //nolint:gosec // test executable
			t.Fatal(err)
		}
		b, err := fleet.LoadBinaries(dir)
		if err != nil {
			t.Fatal(err)
		}
		e.fleet.Binaries = b
		exe := filepath.Join(t.TempDir(), "varde")
		fakeBinary(t, exe, "old")
		a := e.agent(t, e.token(t, time.Hour), t.TempDir())
		if err := a.EnableSelfUpdate(exe); err != nil {
			t.Fatal(err)
		}
		if err := push(t, a); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(exe); !strings.Contains(string(got), "old") || a.Updated() {
			t.Fatalf("replaced by a binary that does not run: %q", got)
		}
	})
}

// Only enrolled agents may download a binary.
func TestBinaryNeedsClientCertificate(t *testing.T) {
	e, _ := updateEnv(t)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: wire.PinnedServer(e.ca.Pin())} //nolint:gosec // pinned
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 10 * time.Second}
	resp, err := c.Get(e.srv.URL + wire.BinaryPath + "?platform=" + agent.Platform())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestLoadBinaries(t *testing.T) {
	b, err := fleet.LoadBinaries(filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(b.Available()) != 0 {
		t.Fatalf("missing directory: %v %v", b.Available(), err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "varde-linux-arm64"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "varde-linux-amd64"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.LoadBinaries(dir); err == nil {
		t.Fatal("a directory in place of a binary was accepted")
	}
	if err := os.Remove(filepath.Join(dir, "varde-linux-amd64")); err != nil {
		t.Fatal(err)
	}
	b, err = fleet.LoadBinaries(dir)
	if err != nil || strings.Join(b.Available(), ",") != "linux/arm64" {
		t.Fatalf("available %v, err %v", b.Available(), err)
	}
	if bin, ok := b.For("linux/arm64"); !ok || len(bin.SHA256) != 64 || bin.Size != 1 {
		t.Fatalf("binary %+v", bin)
	}
}

// An agent without Docker runs on a plain Linux host and is shown as one.
func TestAgentWithoutDockerIsALinuxHost(t *testing.T) {
	e := newEnv(t)
	a, err := agent.New(config.Agent{
		DataDir: t.TempDir(), ServerURL: e.srv.URL, EnrollToken: config.Secret(e.token(t, time.Hour)),
		Interval: 15 * time.Minute, DockerHost: config.DockerHostOff,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UpsertHost(t.Context(), inventory.Host{Name: "web", OS: "Alpine Linux v3.22"}); err != nil {
		t.Fatal(err)
	}
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	if h := agentHost(t, e.st); h.Kind != inventory.HostLinux {
		t.Fatalf("kind %q", h.Kind)
	}
	// Older agents announce nothing and stay Docker hosts.
	if k := (wire.Agent{}).HostKind(); k != inventory.HostDocker {
		t.Fatalf("default kind %q", k)
	}
}

// The agent announces its interface addresses, which tie its host to the
// device the scan finds; older agents announce none and keep the stored.
func TestAgentAddresses(t *testing.T) {
	e := newEnv(t)
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	if err := push(t, a); err != nil {
		t.Fatal(err)
	}
	want, err := agent.InterfaceAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if got := agentHost(t, e.st).Addresses; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("addresses %v, want %v", got, want)
	}
	h := agentHost(t, e.st)
	if err := e.st.TouchAgent(t.Context(), h.ID, store.AgentReport{Name: "x", Interval: time.Hour}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := agentHost(t, e.st).Addresses; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("an older agent's report cleared the addresses: %v", got)
	}
	for _, bad := range [][]string{{"10.0.0.5; rm -rf /"}, {"host.lan"}, make([]string, 33)} {
		if err := wire.ValidAgent(wire.Agent{Name: "x", Addresses: bad}); err == nil {
			t.Errorf("accepted addresses %q", bad)
		}
	}
}

// An agent reports image packages only for images its own containers use,
// and never replaces what Varde itself read (ADR 0033); the server tells
// it whether to read images at all.
func TestAgentImagePackages(t *testing.T) {
	e := newEnv(t)
	e.fleet.ReadImages = func() bool { return true }
	a := e.agent(t, e.token(t, time.Hour), t.TempDir())
	own := "sha256:" + strings.Repeat("a", 64)
	foreign := "sha256:" + strings.Repeat("b", 64)
	trusted := "sha256:" + strings.Repeat("c", 64)
	c := container("c1", "web", "nginx:1.27")
	c.Container.ImageID = own
	c2 := container("c2", "db", "postgres:16")
	c2.Container.ImageID = trusted
	if err := push(t, a, c, c2); err != nil {
		t.Fatal(err)
	}
	// Varde read the trusted image itself.
	if err := e.st.RecordImagePackages(t.Context(), inventory.ImagePackages{ImageID: trusted, Distro: "debian-12", Read: time.Now(),
		Packages: []inventory.Package{{Manager: "dpkg", Name: "libc6", Version: "2.36-9+deb12u14", Source: "glibc"}}}); err != nil {
		t.Fatal(err)
	}
	reader := a.PackageReader()
	for _, p := range []inventory.ImagePackages{
		{ImageID: own, Distro: "debian-12", Read: time.Now(), Packages: []inventory.Package{{Manager: "dpkg", Name: "libc6", Version: "2.36-9", Source: "glibc"}}},
		{ImageID: foreign, Distro: "debian-12", Read: time.Now(), Packages: []inventory.Package{{Manager: "dpkg", Name: "libc6", Version: "2.36-9", Source: "glibc"}}},
		{ImageID: trusted, Distro: "debian-12", Read: time.Now()},
	} {
		if err := reader.Store.RecordImagePackages(t.Context(), p); err != nil {
			t.Fatal(err)
		}
	}
	if err := push(t, a, c, c2); err != nil {
		t.Fatal(err)
	}
	got, err := e.st.ImagePackages(t.Context(), []string{own, foreign, trusted})
	if err != nil {
		t.Fatal(err)
	}
	if p := got[own]; len(p.Packages) != 1 || p.Distro != "debian-12" {
		t.Errorf("own image not stored: %+v", p)
	}
	if _, ok := got[foreign]; ok {
		t.Error("an image of no container of the agent was stored")
	}
	if p := got[trusted]; len(p.Packages) != 1 || p.Packages[0].Version != "2.36-9+deb12u14" {
		t.Errorf("Varde's own read was replaced: %+v", p)
	}
	// Invalid records are refused.
	if err := reader.Store.RecordImagePackages(t.Context(), inventory.ImagePackages{ImageID: own, Distro: "Debian 12; rm", Read: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := push(t, a, c, c2); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("invalid record: %v", err)
	}
}
