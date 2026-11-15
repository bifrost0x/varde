// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHHostKeyNoAuth(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var authTried atomic.Bool
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			authTried.Store(true)
			return nil, ssh.ErrNoAuth
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			authTried.Store(true)
			return nil, ssh.ErrNoAuth
		},
		NoClientAuth: true,
		NoClientAuthCallback: func(ssh.ConnMetadata) (*ssh.Permissions, error) {
			authTried.Store(true)
			return nil, ssh.ErrNoAuth
		},
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { authTried.Store(true) },
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _, _, _ = ssh.NewServerConn(c, cfg) // fails once the client aborts
	}()

	s := &Scanner{ReadTimeout: 5 * time.Second, dial: (&net.Dialer{}).DialContext}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fp, ok := s.sshHostKey(ctx, ln.Addr().String())
	<-done
	if !ok || fp != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("fingerprint %q ok=%v, want %q", fp, ok, ssh.FingerprintSHA256(signer.PublicKey()))
	}
	if authTried.Load() {
		t.Error("the server saw an authentication attempt")
	}
}

func TestSSHHostKeyStalledServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer func() { _ = c.Close() }()
			time.Sleep(3 * time.Second)
		}
	}()
	s := &Scanner{dial: (&net.Dialer{}).DialContext}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, ok := s.sshHostKey(ctx, ln.Addr().String()); ok {
		t.Fatal("got a key from a silent server")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v, deadline not honoured", time.Since(start))
	}
}
