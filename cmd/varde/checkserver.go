// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/bifrost0x/varde/internal/config"
)

// checkServerTimeout bounds the connection test; a firewall that drops
// packets would otherwise keep it waiting for minutes.
const checkServerTimeout = 5 * time.Second

// runCheckServer tests whether this host reaches the server's agent port.
// The push installation runs it right after installing, so the person
// installing sees at once when a firewall or a router blocks the agent
// (ADR 0031). It only opens a TCP connection and sends nothing.
func runCheckServer(stdout, stderr io.Writer) int {
	cfg, err := config.LoadAgent(os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: invalid configuration:\n%v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkServerTimeout)
	defer cancel()
	if err := checkServer(ctx, cfg.ServerURL, (&net.Dialer{}).DialContext); err != nil {
		_, _ = fmt.Fprintf(stdout, "varde: cannot reach %s: %v\n", cfg.ServerURL, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "varde: reaches %s\n", cfg.ServerURL)
	return 0
}

func checkServer(ctx context.Context, server string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server URL")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	conn, err := dial(ctx, "tcp", host)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("no answer within %s (a firewall or router drops the connection)", checkServerTimeout)
		}
		return err
	}
	return conn.Close()
}
