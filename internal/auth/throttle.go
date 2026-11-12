// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"sync"
	"time"
)

// Throttle limits login attempts per account and per client IP with an
// exponentially growing delay after repeated failures. State is in memory
// and bounded; a restart resets it, which is acceptable because the delay
// only slows down online guessing that argon2id already makes expensive.
type Throttle struct {
	mu       sync.Mutex
	entries  map[string]*throttleEntry
	free     int           // failures allowed before delays start
	base     time.Duration // first delay
	max      time.Duration // cap
	maxItems int
	now      func() time.Time
}

type throttleEntry struct {
	failures int
	until    time.Time
	last     time.Time
}

// NewThrottle returns a throttle: 5 free failures, then 1 s doubling up to
// 15 minutes.
func NewThrottle() *Throttle {
	return &Throttle{entries: map[string]*throttleEntry{}, free: 5, base: time.Second, max: 15 * time.Minute, maxItems: 10000, now: time.Now}
}

func keys(username, ip string) []string {
	return []string{"u:" + strings.ToLower(username), "ip:" + ip}
}

// Allowed reports whether an attempt may proceed now, and if not, how long
// to wait.
func (t *Throttle) Allowed(username, ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var wait time.Duration
	for _, k := range keys(username, ip) {
		if e, ok := t.entries[k]; ok && now.Before(e.until) {
			wait = max(wait, e.until.Sub(now))
		}
	}
	return wait == 0, wait
}

// Begin checks and reserves an attempt in one step: the attempt counts as a
// failure until Success or Refund. Concurrent requests therefore cannot all
// pass the check before the first failure is recorded.
func (t *Throttle) Begin(username, ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var wait time.Duration
	for _, k := range keys(username, ip) {
		if e, ok := t.entries[k]; ok && now.Before(e.until) {
			wait = max(wait, e.until.Sub(now))
		}
	}
	if wait > 0 {
		return false, wait
	}
	t.failureLocked(username, ip, now)
	return true, 0
}

// Refund undoes a reservation that turned out not to be a guess (for
// example a malformed request rejected before any secret was checked).
func (t *Throttle) Refund(username, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys(username, ip) {
		t.refundLocked(k)
	}
}

func (t *Throttle) refundLocked(k string) {
	e, ok := t.entries[k]
	if !ok {
		return
	}
	if e.failures--; e.failures <= t.free {
		e.until = time.Time{}
	}
	if e.failures <= 0 {
		delete(t.entries, k)
	}
}

// Failure records a failed attempt.
func (t *Throttle) Failure(username, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failureLocked(username, ip, t.now())
}

func (t *Throttle) failureLocked(username, ip string, now time.Time) {
	if len(t.entries) >= t.maxItems {
		t.evict(now)
	}
	for _, k := range keys(username, ip) {
		e := t.entries[k]
		if e == nil {
			e = &throttleEntry{}
			t.entries[k] = e
		}
		// Old failures expire after a quiet period of the maximum delay.
		if now.Sub(e.last) > t.max {
			e.failures = 0
		}
		e.failures++
		e.last = now
		if n := e.failures - t.free; n > 0 {
			d := t.base << min(n-1, 20)
			e.until = now.Add(min(d, t.max))
		}
	}
}

// Success clears the account's failures and refunds the IP's reservation
// from Begin (the IP's other failures stay: one success must not unlock
// guessing other accounts from the same address).
func (t *Throttle) Success(username, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := keys(username, ip)
	delete(t.entries, k[0])
	t.refundLocked(k[1])
}

func (t *Throttle) evict(now time.Time) {
	for k, e := range t.entries {
		if now.Sub(e.last) > t.max {
			delete(t.entries, k)
		}
	}
	// Still full: drop arbitrary entries rather than grow without bound.
	for k := range t.entries {
		if len(t.entries) < t.maxItems/2 {
			break
		}
		delete(t.entries, k)
	}
}
