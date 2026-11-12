// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/fleet/wire"
)

// maxBinaryBytes bounds a downloaded agent binary.
const maxBinaryBytes = 256 << 20

// Platform is this binary's GOOS/GOARCH, as the server names its binaries.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// EnableSelfUpdate lets the agent replace exe with the binary the server
// ships. It fails when exe cannot be replaced, for example in the
// read-only container image; the agent then keeps running as it is.
func (a *Agent) EnableSelfUpdate(exe string) error {
	exe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve own binary: %w", err)
	}
	sum, err := fileSHA256(exe)
	if err != nil {
		return err
	}
	probe, err := os.CreateTemp(filepath.Dir(exe), ".varde-update-*")
	if err != nil {
		return fmt.Errorf("%s is not writable: %w", filepath.Dir(exe), err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	a.mu.Lock()
	a.exe, a.selfSHA = exe, sum
	a.mu.Unlock()
	return nil
}

// Updated reports whether the agent replaced its binary and stopped so that
// its supervisor starts the new one.
func (a *Agent) Updated() bool { return a.updated.Load() }

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the agent's own binary
	if err != nil {
		return "", fmt.Errorf("read own binary: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash own binary: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// maybeUpdate installs the offered binary when it differs from the running
// one, then stops the agent. Failures are logged and retried with the next
// report; the running binary stays.
func (a *Agent) maybeUpdate(ctx context.Context, u *wire.Update) {
	a.mu.Lock()
	exe, self, stop := a.exe, a.selfSHA, a.stop
	a.mu.Unlock()
	if u == nil || exe == "" || !a.cfg.AutoUpdate || strings.EqualFold(u.SHA256, self) {
		return
	}
	if err := a.install(ctx, exe, u); err != nil {
		a.log.Warn("agent update failed; keeping the running version", "offered", u.Version, "err", err)
		return
	}
	a.log.Info("agent updated; restarting", "from", buildinfo.Version, "to", u.Version)
	a.updated.Store(true)
	if stop != nil {
		stop()
	}
}

// install downloads the binary over the pinned connection, checks its
// SHA-256 against the report answer and that it runs, and replaces exe
// atomically.
func (a *Agent) install(ctx context.Context, exe string, u *wire.Update) error {
	if len(u.SHA256) != 64 {
		return errors.New("the server offered no valid checksum")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	target := strings.TrimRight(a.cfg.ServerURL, "/") + wire.BinaryPath + "?platform=" + url.QueryEscape(Platform())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	// The download may take longer than a report; the context bounds it.
	client := *a.client
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: status %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".varde-update-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err == nil && n > maxBinaryBytes {
		err = errors.New("the binary is too large")
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, u.SHA256) {
		return fmt.Errorf("checksum mismatch: got %s, the server announced %s", got, u.SHA256)
	}
	if err := os.Chmod(tmp.Name(), 0o750); err != nil { //nolint:gosec // an executable, owner and group only
		return err
	}
	// A binary that does not start (wrong platform, truncated) must not
	// replace one that does.
	vctx, vcancel := context.WithTimeout(ctx, 30*time.Second)
	defer vcancel()
	out, err := exec.CommandContext(vctx, tmp.Name(), "version").Output() //nolint:gosec // checksum-verified binary in the agent's own directory
	if err != nil {
		return fmt.Errorf("the new binary does not run: %w", err)
	}
	if !strings.HasPrefix(string(out), "varde") {
		return errors.New("the new binary does not answer like varde")
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	return nil
}
