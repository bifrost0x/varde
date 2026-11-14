// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/policy"
	"github.com/bifrost0x/varde/internal/store"
)

var update = flag.Bool("update", false, "rewrite golden files")

func item(id string, p policy.Priority) Item {
	return Item{
		FindingID: id, AppID: "immich", AppName: "Immich", WorkloadName: "immich_server", HostName: "nas",
		Version: "1.120.0", AdvisoryID: "GHSA-" + id, Aliases: []string{"CVE-2026-" + id}, Summary: "Path traversal in asset upload",
		Severity: "critical", CVSS: 9.8, KEV: p == policy.P1, EPSS: 0.42, Exposure: "public",
		ExposureEvidence: []string{"traefik router immich serves photos.example.com"}, FixedIn: "1.121.0",
		AdvisoryURL: "https://github.com/immich-app/immich/security/advisories/GHSA-" + id,
		FindingURL:  "https://varde.example.com/findings/" + id, Priority: p, MatchState: "affected",
	}
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	later := now.Add(time.Hour)
	earlier := now.Add(-time.Hour)
	unverified := item("u", policy.None)
	unverified.MatchState = "unverified"
	cands := []Candidate{
		{Item: item("p1-new", policy.P1), State: store.StateOpen},
		{Item: item("p1-done", policy.P1), State: store.StateOpen, LastNotified: policy.P1},
		{Item: item("p1-escalated", policy.P1), State: store.StateOpen, LastNotified: policy.P2},
		{Item: item("p1-ack", policy.P1), State: store.StateAcknowledged, LastNotified: policy.P2},
		{Item: item("p2-ack", policy.P2), State: store.StateAcknowledged},
		{Item: item("p1-snoozed", policy.P1), State: store.StateSnoozed, SnoozedUntil: &later},
		{Item: item("p1-snooze-over", policy.P1), State: store.StateSnoozed, SnoozedUntil: &earlier},
		{Item: item("p1-suppressed", policy.P1), State: store.StateSuppressed},
		{Item: item("p2-new", policy.P2), State: store.StateOpen},
		{Item: item("p2-queued", policy.P2), State: store.StateOpen, DigestPending: policy.P2},
		{Item: item("p2-from-p3", policy.P2), State: store.StateOpen, LastNotified: policy.P3, DigestPending: policy.P3},
		{Item: item("p3-new", policy.P3), State: store.StateOpen},
		{Item: item("p3-after-p2", policy.P3), State: store.StateOpen, LastNotified: policy.P2},
		{Item: unverified, State: store.StateOpen},
	}
	d := Decide(cands, now)
	var immediate []string
	for _, it := range d.Immediate {
		immediate = append(immediate, it.FindingID)
	}
	want := []string{"p1-new", "p1-escalated", "p1-ack", "p1-snooze-over"}
	if strings.Join(immediate, ",") != strings.Join(want, ",") {
		t.Errorf("immediate %v, want %v", immediate, want)
	}
	if got := strings.Join(d.Queue[policy.P2], ","); got != "p2-new,p2-from-p3" {
		t.Errorf("P2 queue %s", got)
	}
	if got := strings.Join(d.Queue[policy.P3], ","); got != "p3-new" {
		t.Errorf("P3 queue %s", got)
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestRendering(t *testing.T) {
	m := Immediate([]Item{item("1", policy.P1)})
	golden(t, "immediate_single.txt", m.Title+"\n\n"+m.Body)

	two := Immediate([]Item{item("1", policy.P1), item("2", policy.P1)})
	// Both are findings of one container: one update to install.
	if two.Title != "[varde] P1: 1 urgent update (2 findings)" {
		t.Errorf("multi title %q", two.Title)
	}

	low := item("3", policy.P3)
	low.Exposure, low.CVSS, low.Severity, low.FixedIn, low.KEV, low.EPSS = "lan", 3.1, "low", "", false, 0
	attention := item("4", policy.None)
	attention.MatchState = "unverified"
	d, ok := Digest(KindDigestWeekly, []Item{item("2", policy.P2), low}, []Item{attention}, nil, nil)
	if !ok {
		t.Fatal("digest not rendered")
	}
	golden(t, "digest_weekly.txt", d.Title+"\n\n"+d.Body)

	if _, ok := Digest(KindDigestDaily, nil, nil, nil, nil); ok {
		t.Error("empty digest rendered")
	}

	// Upstream text cannot inject lines or headers.
	evil := item("5", policy.P1)
	evil.Summary = "line1\r\nBcc: attacker@example.com\x00"
	evil.AppName = "Immich\nSubject: spoof"
	m = Immediate([]Item{evil})
	if strings.Contains(m.Title, "\n") || strings.Contains(m.Body, "\nBcc:") || strings.Contains(m.Body, "\x00") {
		t.Errorf("injection not neutralised:\n%q\n%q", m.Title, m.Body)
	}
	for _, s := range []string{m.Title, m.Body} {
		for _, r := range s {
			if r > 0x1F000 {
				t.Errorf("emoji-range character in output: %q", s)
			}
		}
	}
}

func TestNtfyGotifyWebhook(t *testing.T) {
	type got struct {
		path   string
		header http.Header
		body   []byte
	}
	var mu sync.Mutex
	var reqs []got
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, got{r.URL.Path, r.Header.Clone(), b})
		mu.Unlock()
	}))
	defer srv.Close()
	hc := httpx.New(httpx.Options{AllowHTTP: true})
	m := Immediate([]Item{item("1", policy.P1)})

	if err := (&Ntfy{HTTP: hc, URL: srv.URL + "/varde", Token: "tk"}).Send(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if err := (&Ntfy{HTTP: hc, URL: srv.URL + "/a/b"}).Send(t.Context(), m); err == nil {
		t.Error("nested ntfy topic accepted")
	}
	if err := (&Gotify{HTTP: hc, URL: srv.URL + "/", Token: "gt"}).Send(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1794178806, 0)
	if err := (&Webhook{HTTP: hc, URL: srv.URL + "/hook", Secret: "s3cret", Now: func() time.Time { return now }}).Send(t.Context(), m); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reqs) != 3 {
		t.Fatalf("requests: %d", len(reqs))
	}
	var nt map[string]any
	_ = json.Unmarshal(reqs[0].body, &nt)
	if reqs[0].path != "/" || nt["topic"] != "varde" || nt["priority"] != float64(5) || reqs[0].header.Get("Authorization") != "Bearer tk" {
		t.Errorf("ntfy: %s %v %v", reqs[0].path, nt, reqs[0].header)
	}
	if reqs[1].path != "/message" || reqs[1].header.Get("X-Gotify-Key") != "gt" || strings.Contains(reqs[1].path, "token") {
		t.Errorf("gotify: %s %v", reqs[1].path, reqs[1].header)
	}
	ts := reqs[2].header.Get(HeaderTimestamp)
	sig := reqs[2].header.Get(HeaderSignature)
	if ts != "1794178806" || sig != "sha256="+Sign("s3cret", ts, reqs[2].body) {
		t.Errorf("webhook signature: %s %s", ts, sig)
	}
	var wh map[string]any
	_ = json.Unmarshal(reqs[2].body, &wh)
	if wh["version"] != float64(1) || wh["kind"] != KindImmediate || len(wh["items"].([]any)) != 1 {
		t.Errorf("webhook body: %v", wh)
	}
}

// fakeSMTP is a minimal SMTP server for tests (no TLS).
func fakeSMTP(t *testing.T, offerStartTLS bool) (addr string, received chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	received = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		write("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					received <- data.String()
					write("250 queued")
					continue
				}
				data.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				if offerStartTLS {
					write("250-fake\r\n250 STARTTLS")
				} else {
					write("250-fake\r\n250 AUTH PLAIN")
				}
			case strings.HasPrefix(cmd, "AUTH"):
				write("235 ok")
			case strings.HasPrefix(cmd, "DATA"):
				inData = true
				write("354 go")
			case strings.HasPrefix(cmd, "QUIT"):
				write("221 bye")
				return
			default:
				write("250 ok")
			}
		}
	}()
	return ln.Addr().String(), received
}

func TestSMTP(t *testing.T) {
	addr, received := fakeSMTP(t, false)
	host, port, _ := net.SplitHostPort(addr)
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	m := Immediate([]Item{item("1", policy.P1)})
	m.Title = "[varde] P1 Immich: CVE-2026-1, Größe"
	s := &SMTP{Host: host, Port: p, Username: "u", Password: "pw", From: "varde@example.com", To: []string{"ops@example.com"}, TLSMode: SMTPNone}
	if err := s.Send(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	msg := <-received
	for _, want := range []string{"From: varde@example.com", "To: ops@example.com", "Subject: =?utf-8?q?", "Content-Type: text/plain; charset=utf-8", "Action: update to 1.121.0 or later"} {
		if !strings.Contains(msg, want) {
			t.Errorf("mail lacks %q:\n%s", want, msg)
		}
	}

	// STARTTLS required but not offered: refuse before sending credentials.
	addr2, _ := fakeSMTP(t, false)
	host2, port2, _ := net.SplitHostPort(addr2)
	p2 := 0
	for _, c := range port2 {
		p2 = p2*10 + int(c-'0')
	}
	err := (&SMTP{Host: host2, Port: p2, Username: "u", Password: "pw", From: "a@example.com", To: []string{"b@example.com"}, TLSMode: SMTPStartTLS}).Send(t.Context(), m)
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("missing STARTTLS: %v", err)
	}
}

type memStore struct {
	mu       sync.Mutex
	notified map[string]string
	queued   map[string]string
	log      []store.NotificationEntry
	states   map[string]store.SourceState
	// markErr makes MarkNotified fail, as a database that refuses writes.
	markErr error
}

func newMemStore() *memStore {
	return &memStore{notified: map[string]string{}, queued: map[string]string{}, states: map[string]store.SourceState{}}
}

func (m *memStore) MarkNotified(_ context.Context, ids []string, p string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.markErr != nil {
		return m.markErr
	}
	for _, id := range ids {
		m.notified[id] = p
		delete(m.queued, id)
	}
	return nil
}

func (m *memStore) QueueDigest(_ context.Context, ids []string, p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		m.queued[id] = p
	}
	return nil
}

func (m *memStore) LogNotification(_ context.Context, e store.NotificationEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log = append(m.log, e)
	return nil
}

func (m *memStore) SourceState(_ context.Context, source, key string) (store.SourceState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.states[source+key]
	if !ok {
		st = store.SourceState{Source: source, Key: key}
	}
	return st, nil
}

func (m *memStore) PutSourceState(_ context.Context, st store.SourceState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[st.Source+st.Key] = st
	return nil
}

type fakeChannel struct {
	mu    sync.Mutex
	sent  []Message
	fails int
}

func (*fakeChannel) Name() string { return "fake" }

func (f *fakeChannel) Send(_ context.Context, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return errors.New("unreachable")
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeChannel) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

// candidates simulates the pipeline: it reflects the store's notified and
// queued state back into the candidates, like the real implementation.
func candidates(ms *memStore, base []Candidate) func(context.Context) ([]Candidate, error) {
	return func(context.Context) ([]Candidate, error) {
		ms.mu.Lock()
		defer ms.mu.Unlock()
		out := make([]Candidate, len(base))
		for i, c := range base {
			c.LastNotified = policy.Priority(ms.notified[c.Item.FindingID])
			c.DigestPending = policy.Priority(ms.queued[c.Item.FindingID])
			out[i] = c
		}
		return out, nil
	}
}

func TestServiceImmediateNoRepeatEscalationAndRetry(t *testing.T) {
	ms := newMemStore()
	ch := &fakeChannel{fails: 1}
	base := []Candidate{{Item: item("a", policy.P1), State: store.StateOpen}}
	svc := NewService(Config{
		Channels: []Channel{ch}, Store: ms, Candidates: candidates(ms, base), Log: slog.New(slog.DiscardHandler),
		RetryDelays: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond},
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go svc.Run(ctx)

	start := time.Now()
	if err := svc.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	// A second evaluation while the first is in flight must not duplicate.
	if err := svc.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return ch.count() == 1 })
	if time.Since(start) > 60*time.Second {
		t.Fatal("P1 not delivered within 60 s")
	}
	waitFor(t, func() bool { ms.mu.Lock(); defer ms.mu.Unlock(); return ms.notified["a"] == "P1" })

	// Re-scans: no repeat.
	for range 3 {
		if err := svc.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if ch.count() != 1 {
		t.Fatalf("repeated notification: %d", ch.count())
	}
	ms.mu.Lock()
	failed, sent := 0, 0
	for _, e := range ms.log {
		if e.Status == "failed" {
			failed++
		} else {
			sent++
		}
	}
	ms.mu.Unlock()
	if failed != 1 || sent != 1 {
		t.Errorf("log failed=%d sent=%d", failed, sent)
	}
}

func TestServiceEscalationFromDigest(t *testing.T) {
	ms := newMemStore()
	ch := &fakeChannel{}
	base := []Candidate{{Item: item("b", policy.P2), State: store.StateOpen}}
	cands := candidates(ms, base)
	svc := NewService(Config{Channels: []Channel{ch}, Store: ms, Candidates: func(ctx context.Context) ([]Candidate, error) { return cands(ctx) }, Log: slog.New(slog.DiscardHandler),
		DigestWeekday: (time.Now().Weekday() + 1) % 7, // not the weekly day
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go svc.Run(ctx)

	if err := svc.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if ms.queued["b"] != "P2" || ch.count() != 0 {
		t.Fatalf("P2 must be queued, not sent: %v %d", ms.queued, ch.count())
	}
	svc.RunDigests(ctx)
	if ch.count() != 1 || ch.sent[0].Kind != KindDigestDaily || ms.notified["b"] != "P2" {
		t.Fatalf("daily digest: %d %+v", ch.count(), ms.notified)
	}
	// Nothing pending: the next digest is not sent.
	svc.RunDigests(ctx)
	if ch.count() != 1 {
		t.Fatal("empty digest sent")
	}
	// KEV listing later escalates the finding to P1: immediate notification.
	base[0].Item = item("b", policy.P1)
	if err := svc.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return ch.count() == 2 })
	if ch.sent[1].Kind != KindImmediate {
		t.Fatalf("escalation kind %s", ch.sent[1].Kind)
	}
}

func TestWeeklyDigestAttentionOnce(t *testing.T) {
	ms := newMemStore()
	ch := &fakeChannel{}
	unv := item("u", policy.None)
	unv.MatchState = "unverified"
	base := []Candidate{{Item: unv, State: store.StateOpen, FirstSeen: time.Now().Add(-time.Hour)}}
	svc := NewService(Config{Channels: []Channel{ch}, Store: ms, Candidates: candidates(ms, base), Log: slog.New(slog.DiscardHandler),
		DigestWeekday: time.Now().Weekday()})
	svc.RunDigests(t.Context())
	if ch.count() != 1 || ch.sent[0].Kind != KindDigestWeekly || !strings.Contains(ch.sent[0].Body, "Needs attention") {
		t.Fatalf("weekly attention: %d", ch.count())
	}
	if ms.notified["u"] != "" {
		t.Error("unverified item recorded as notified")
	}
	svc.RunDigests(t.Context())
	if ch.count() != 1 {
		t.Error("attention item repeated")
	}
}

func TestLastSlot(t *testing.T) {
	loc := time.FixedZone("CET", 3600)
	now := time.Date(2026, 11, 8, 7, 30, 0, 0, loc)
	svc := NewService(Config{DigestHour: 8, Location: loc, Now: func() time.Time { return now }})
	if got := svc.lastSlot(now); !got.Equal(time.Date(2026, 11, 7, 8, 0, 0, 0, loc)) {
		t.Errorf("before the hour: %v", got)
	}
	now = time.Date(2026, 11, 8, 8, 0, 0, 0, loc)
	if got := svc.lastSlot(now); !got.Equal(now) {
		t.Errorf("at the hour: %v", got)
	}
	// The weekly digest missed on its day is due the next day, once.
	svc.cfg.DigestWeekday = time.Sunday
	mon := time.Date(2026, 11, 9, 9, 0, 0, 0, loc)
	if !svc.weeklyDue(mon, time.Sunday, time.Date(2026, 11, 1, 8, 0, 0, 0, loc)) {
		t.Error("missed weekly digest not due")
	}
	if svc.weeklyDue(mon, time.Sunday, time.Date(2026, 11, 8, 8, 5, 0, 0, loc)) {
		t.Error("weekly digest due again")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The weekly digest lists notified findings resolved since the last one,
// once; resolved findings never notify on their own.
func TestWeeklyDigestResolvedOnce(t *testing.T) {
	ms := newMemStore()
	ch := &fakeChannel{}
	resolvedAt := time.Now().Add(-time.Hour)
	done := item("r", policy.P2)
	silent := item("s", policy.P3)
	base := []Candidate{
		{Item: done, State: store.StateResolved, LastNotified: policy.P2, ResolvedAt: &resolvedAt},
		// Never notified: the user never heard of it, so no news either.
		{Item: silent, State: store.StateResolved, ResolvedAt: &resolvedAt},
	}
	ms.notified["r"] = "P2" // notified earlier
	svc := NewService(Config{Channels: []Channel{ch}, Store: ms, Candidates: candidates(ms, base), Log: slog.New(slog.DiscardHandler),
		DigestWeekday: time.Now().Weekday()})
	if err := svc.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ch.count() != 0 || len(ms.queued) != 0 {
		t.Fatal("a resolved finding notified")
	}
	svc.RunDigests(t.Context())
	if ch.count() != 1 || !strings.Contains(ch.sent[0].Title, "1 resolved") || !strings.Contains(ch.sent[0].Body, "Resolved since the last weekly digest") ||
		!strings.Contains(ch.sent[0].Body, done.AdvisoryID) || strings.Contains(ch.sent[0].Body, silent.AdvisoryID) {
		t.Fatalf("weekly resolved: %d %+v", ch.count(), ch.sent)
	}
	svc.RunDigests(t.Context())
	if ch.count() != 1 {
		t.Error("resolved item repeated")
	}
}

// Many findings of one package become one block with the update that
// fixes them, instead of one block each.
func TestDigestGroupsPackages(t *testing.T) {
	var items []Item
	for i, fixed := range []string{"2.36-9+deb12u3", "2.36-9+deb12u14", "2.36-9+deb12u4", "2.36-9+deb12u7", "2.36-9+deb12u11", "2.36-9+deb12u14", "2.36-9+deb12u14"} {
		items = append(items, Item{
			FindingID: fmt.Sprint(i), AppID: "os:Debian:12/glibc", AppName: "glibc (Debian 12 package)", WorkloadName: "glibc", HostName: "web",
			Version: "2.36-9", AdvisoryID: fmt.Sprintf("DEBIAN-CVE-2026-%d", i), Aliases: []string{fmt.Sprintf("CVE-2026-%d", i)},
			FixedIn: fixed, Priority: policy.P3, Exposure: "unknown", MatchState: "affected",
			FindingURL: fmt.Sprintf("https://varde.example.com/findings/%d", i), KEV: i == 3,
		})
	}
	other := item("9", policy.P3)
	other.Exposure, other.CVSS, other.Severity = "lan", 3.1, "low"
	d, ok := Digest(KindDigestWeekly, append(items, other), nil, nil, nil)
	if !ok {
		t.Fatal("digest not rendered")
	}
	golden(t, "digest_grouped.txt", d.Title+"\n\n"+d.Body)
	if len(d.Items) != 8 {
		t.Errorf("message items %d, want every finding for the channels' data", len(d.Items))
	}
}

// A package of a container's image is fixed by a newer image, not by a
// package update on the host.
func TestImageFindingAction(t *testing.T) {
	it := Item{FindingID: "1", AppID: "os:Debian:12/glibc", AppName: "glibc (Debian 12 package)", WorkloadName: "immich_server", HostName: "nas",
		Version: "2.36-9", AdvisoryID: "DEBIAN-CVE-2023-4911", FixedIn: "2.36-9+deb12u3", Priority: policy.P3, MatchState: "affected", Image: true}
	d, ok := Digest(KindDigestWeekly, []Item{it}, nil, nil, nil)
	if !ok || !strings.Contains(d.Body, "glibc (Debian 12 package) in the image of immich_server on nas, version 2.36-9") ||
		!strings.Contains(d.Body, "pull a newer image whose glibc is 2.36-9+deb12u3 or later and recreate the container") {
		t.Fatalf("digest:\n%s", d.Body)
	}
}

// A finding on an attack path says so in every message; noise says it only
// where the digest is verbose.
func TestAttackPathLine(t *testing.T) {
	it := Item{FindingID: "1", AppID: "immich", AppName: "Immich", WorkloadName: "immich_server", HostName: "nas", Version: "1.120.0",
		AdvisoryID: "GHSA-x", FixedIn: "1.121.0", Priority: policy.P1, MatchState: "affected",
		PathClass: "path-internet", PathReason: "opens an attack path from the internet"}
	d, ok := Digest(KindDigestWeekly, []Item{it}, nil, nil, nil)
	if !ok || !strings.Contains(d.Body, "Attack path: opens an attack path from the internet") {
		t.Fatalf("digest:\n%s", d.Body)
	}
}

// An update is a container or the system packages of a host. Packages of
// images belong to their container, not to the host's package update.
func TestUpdatesCountContainersAndHosts(t *testing.T) {
	items := []Item{
		{WorkloadName: "a", HostName: "h", AppID: "os:Alpine:v3.24/zlib", Image: true},
		{WorkloadName: "a", HostName: "h", AppID: "immich"},
		{WorkloadName: "b", HostName: "h", AppID: "os:Alpine:v3.24/zlib", Image: true},
		{WorkloadName: "openssl", HostName: "h", AppID: "os:Debian:13/openssl"},
		{WorkloadName: "glibc", HostName: "h", AppID: "os:Debian:13/glibc"},
	}
	if n := updates(items); n != 3 {
		t.Errorf("updates = %d, want 3 (container a, container b, the host's packages)", n)
	}
}

// A message names the version the finding's page names: the update, with
// the advisory's own fixed version beside it when the two differ, and one
// update for findings that share it.
func TestMessageNamesTheUpdate(t *testing.T) {
	one := item("1", policy.P1)
	one.FixedIn, one.Update = "1.120.1", "1.121.1"
	if text := Immediate([]Item{one}).Body; !strings.Contains(text, "Action: update to 1.121.1 (this advisory is fixed from 1.120.1 on)") {
		t.Errorf("single finding:\n%s", text)
	}
	same := item("2", policy.P1)
	same.Update = "1.121.0" // equals its fixed version
	if text := Immediate([]Item{same}).Body; !strings.Contains(text, "Action: update to 1.121.0 or later") {
		t.Errorf("update equal to the fix:\n%s", text)
	}
	a, b := item("3", policy.P1), item("4", policy.P1)
	a.FixedIn, b.FixedIn = "1.120.1", "1.121.0"
	a.Update, b.Update = "1.121.1", "1.121.1"
	if fixes, target := groupTarget([]Item{a, b}); fixes != 2 || target != "1.121.1" {
		t.Errorf("group target = %d %q", fixes, target)
	}
}
