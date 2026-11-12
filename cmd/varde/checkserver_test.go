// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCheckServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	d := (&net.Dialer{}).DialContext
	if err := checkServer(t.Context(), "https://"+ln.Addr().String(), d); err != nil {
		t.Fatalf("reachable: %v", err)
	}
	// A dropping firewall: the dial only ends with the deadline.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	hang := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, errors.New("i/o timeout")
	}
	if err := checkServer(ctx, "https://10.10.2.150:8443", hang); err == nil || !strings.Contains(err.Error(), "drops") {
		t.Fatalf("dropped: %v", err)
	}
}
