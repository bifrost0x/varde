// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// ProtoSNMP marks an SNMP answer.
const ProtoSNMP = "snmp"

// SNMP holds what the scan sends to read a device's system description:
// a v2c community, or a v3 user with SHA-256 authentication and AES
// privacy. Only reads of three system objects are sent.
type SNMP struct {
	Community           string
	User, Auth, Privacy string
}

// Enabled reports whether any credential is set.
func (c *SNMP) Enabled() bool {
	return c != nil && (c.Community != "" || (c.User != "" && c.Auth != ""))
}

// The system group objects read: description, object ID, name.
const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
)

const snmpTimeout = 1500 * time.Millisecond

// snmp reads the system description of a device, which names switches,
// UPS, printers and NAS with their firmware.
func (s *Scanner) snmp(ctx context.Context, a netip.Addr) (Service, string, bool) {
	if !s.SNMP.Enabled() || (s.inScope != nil && !s.inScope(a)) {
		return Service{}, "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*snmpTimeout)
	defer cancel()
	g := &gosnmp.GoSNMP{
		Context: ctx, Target: a.String(), Port: portOr(s.snmpPort, 161), Transport: "udp",
		Timeout: snmpTimeout, Retries: 0, MaxOids: 3, ExponentialTimeout: false,
	}
	if s.SNMP.User != "" && s.SNMP.Auth != "" {
		level := gosnmp.AuthNoPriv
		if s.SNMP.Privacy != "" {
			level = gosnmp.AuthPriv
		}
		g.Version, g.SecurityModel, g.MsgFlags = gosnmp.Version3, gosnmp.UserSecurityModel, level
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: s.SNMP.User, AuthenticationProtocol: gosnmp.SHA256,
			AuthenticationPassphrase: s.SNMP.Auth, PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: s.SNMP.Privacy}
		if level == gosnmp.AuthNoPriv {
			g.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyProtocol = gosnmp.NoPriv
		}
	} else {
		g.Version, g.Community = gosnmp.Version2c, s.SNMP.Community
	}
	if err := g.Connect(); err != nil {
		return Service{}, "", false
	}
	defer func() { _ = g.Conn.Close() }()
	res, err := g.Get([]string{oidSysDescr, oidSysObjectID, oidSysName})
	if err != nil || res == nil || res.Error != gosnmp.NoError {
		return Service{}, "", false
	}
	var descr, name string
	for _, v := range res.Variables {
		b, ok := v.Value.([]byte)
		if !ok {
			continue
		}
		switch v.Name {
		case oidSysDescr:
			// The first line names the product; later lines are build
			// details.
			first, _, _ := strings.Cut(string(b), "\n")
			descr = printable(first, 120)
		case oidSysName:
			name = printable(string(b), 63)
		}
	}
	if descr == "" {
		return Service{}, "", false
	}
	return Service{Port: 161, Proto: ProtoSNMP, Product: descr}, name, true
}

type snmpAnswer struct {
	svc  Service
	name string
}

// snmpScan asks the addresses that answered the scan, at most InFlight
// at a time.
func (s *Scanner) snmpScan(ctx context.Context, addrs []netip.Addr, answered func(netip.Addr) bool) map[netip.Addr]snmpAnswer {
	out := map[netip.Addr]snmpAnswer{}
	var mu sync.Mutex
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range max(1, s.InFlight) {
		wg.Go(func() {
			for a := range jobs {
				if svc, name, ok := s.snmp(ctx, a); ok {
					mu.Lock()
					out[a] = snmpAnswer{svc, name}
					mu.Unlock()
				}
			}
		})
	}
feed:
	for _, a := range addrs {
		if !answered(a) {
			continue
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- a:
		}
	}
	close(jobs)
	wg.Wait()
	return out
}
