// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"slices"
	"strings"

	"github.com/bifrost0x/varde/internal/distro"
)

// servicesByPort names the source packages that commonly serve a port. The
// package actually installed on the host decides: a port maps only to
// packages the host has.
var servicesByPort = map[uint16][]string{
	21:    {"vsftpd", "proftpd-dfsg", "proftpd", "pure-ftpd"},
	22:    {"openssh", "dropbear"},
	25:    {"postfix", "exim4", "exim", "sendmail", "opensmtpd"},
	53:    {"bind9", "bind", "dnsmasq", "unbound", "pdns", "pdns-recursor", "knot"},
	80:    {"nginx", "apache2", "httpd", "lighttpd", "caddy", "haproxy", "varnish"},
	110:   {"dovecot"},
	111:   {"rpcbind"},
	123:   {"ntp", "ntpsec", "chrony", "openntpd"},
	139:   {"samba"},
	143:   {"dovecot", "cyrus-imapd"},
	161:   {"net-snmp"},
	389:   {"openldap", "389-ds-base"},
	443:   {"nginx", "apache2", "httpd", "lighttpd", "caddy", "haproxy"},
	445:   {"samba"},
	465:   {"postfix", "exim4", "exim"},
	587:   {"postfix", "exim4", "exim"},
	631:   {"cups"},
	636:   {"openldap", "389-ds-base"},
	993:   {"dovecot", "cyrus-imapd"},
	995:   {"dovecot"},
	1194:  {"openvpn"},
	2049:  {"nfs-utils", "nfs-kernel-server"},
	3128:  {"squid"},
	3306:  {"mariadb", "mariadb-10.11", "mariadb-11.8", "mysql-8.0", "mysql-8.4", "mysql"},
	3389:  {"xrdp"},
	5060:  {"asterisk"},
	5432:  {"postgresql"},
	5900:  {"tigervnc", "x11vnc"},
	6379:  {"redis", "valkey"},
	8006:  {"pve-manager"},
	8080:  {"tomcat9", "tomcat10", "jetty9"},
	11211: {"memcached"},
	27017: {"mongodb"},
}

// productPackages maps a word of a scan's product banner to source
// packages: a banner beats the port's guess.
var productPackages = map[string][]string{
	"openssh":    {"openssh"},
	"dropbear":   {"dropbear"},
	"nginx":      {"nginx"},
	"apache":     {"apache2", "httpd"},
	"httpd":      {"apache2", "httpd"},
	"tomcat":     {"tomcat9", "tomcat10", "tomcat11"},
	"lighttpd":   {"lighttpd"},
	"postfix":    {"postfix"},
	"exim":       {"exim4", "exim"},
	"dovecot":    {"dovecot"},
	"samba":      {"samba"},
	"dnsmasq":    {"dnsmasq"},
	"bind":       {"bind9", "bind"},
	"unbound":    {"unbound"},
	"mariadb":    {"mariadb"},
	"mysql":      {"mysql-8.0", "mysql-8.4", "mysql", "mariadb"},
	"postgresql": {"postgresql"},
	"redis":      {"redis"},
	"vsftpd":     {"vsftpd"},
	"proftpd":    {"proftpd-dfsg", "proftpd"},
	"cups":       {"cups"},
	"squid":      {"squid"},
	"openvpn":    {"openvpn"},
}

// libraries are the source packages a network service commonly links and
// whose flaws are reachable through it: TLS, compression, parsers,
// authentication. A flaw in one counts as indirect evidence.
var libraries = map[string][]string{
	"openssh":     {"openssl", "zlib", "glibc", "krb5", "libxcrypt", "pam"},
	"nginx":       {"openssl", "zlib", "pcre2", "pcre3", "libxml2", "glibc"},
	"apache2":     {"openssl", "zlib", "pcre2", "libxml2", "expat", "nghttp2", "apr", "apr-util", "glibc"},
	"httpd":       {"openssl", "zlib", "pcre2", "libxml2", "expat", "nghttp2", "apr", "apr-util", "glibc"},
	"lighttpd":    {"openssl", "zlib", "pcre2", "glibc"},
	"haproxy":     {"openssl", "pcre2", "glibc"},
	"postfix":     {"openssl", "cyrus-sasl2", "glibc"},
	"exim4":       {"openssl", "gnutls28", "cyrus-sasl2", "glibc"},
	"dovecot":     {"openssl", "glibc"},
	"samba":       {"gnutls28", "krb5", "glibc", "ldb", "talloc", "tdb"},
	"bind9":       {"openssl", "libxml2", "libuv1", "nghttp2", "glibc"},
	"unbound":     {"openssl", "expat", "glibc"},
	"dnsmasq":     {"nettle", "glibc"},
	"openldap":    {"openssl", "gnutls28", "cyrus-sasl2", "glibc"},
	"cups":        {"gnutls28", "openssl", "glibc"},
	"squid":       {"openssl", "gnutls28", "libxml2", "expat", "glibc"},
	"openvpn":     {"openssl", "lzo2", "glibc"},
	"xrdp":        {"openssl", "glibc"},
	"redis":       {"openssl", "glibc"},
	"pve-manager": {"openssl", "glibc", "perl"},
}

// servicePackages are the installed packages that may serve a port: the
// port's usual servers and the ones a word of the product banner names
// ("OpenSSH_9.2p1", "Apache Tomcat"). A banner adds candidates and never
// removes the port's: banners are often generic or wrong.
func servicePackages(port uint16, _ string, product string, installed map[string]bool) []string {
	cands := append([]string(nil), servicesByPort[port]...)
	for _, word := range strings.FieldsFunc(strings.ToLower(product), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		cands = append(cands, productPackages[word]...)
	}
	var out []string
	for _, c := range cands {
		for name := range installed {
			if (name == c || versioned(name, c)) && !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out
}

// versioned matches packages that carry a version in their name, such as
// postgresql-16 for postgresql.
func versioned(name, base string) bool {
	rest, ok := strings.CutPrefix(name, base+"-")
	return ok && rest != "" && rest[0] >= '0' && rest[0] <= '9'
}

// librariesOf returns the libraries a service package uses.
func librariesOf(src string) []string {
	if l, ok := libraries[src]; ok {
		return l
	}
	for base, l := range libraries {
		if versioned(src, base) {
			return l
		}
	}
	return nil
}

// kernelPackage reports whether a checked package is a kernel.
func kernelPackage(src string) bool { return distro.IsKernel(src) }

// ServicePort reports whether Varde knows a server package for a port.
func ServicePort(port uint16) bool { _, ok := servicesByPort[port]; return ok }

// NetworkPackage reports whether a source package is a server or a library
// network services commonly use: a flaw in it may be reachable through a
// service even when Varde cannot see which.
func NetworkPackage(src string) bool { return networkSet[src] }

// ServerPackage reports whether a source package is a server that answers
// on a port (nginx, samba, openssh), as opposed to a library a service
// links. A flaw in it is a flaw in a service, not in something the service
// may or may not use.
func ServerPackage(src string) bool { return serverSet[src] }

var serverSet = func() map[string]bool {
	m := map[string]bool{}
	for _, pkgs := range servicesByPort {
		for _, p := range pkgs {
			m[p] = true
		}
	}
	return m
}()

var networkSet = func() map[string]bool {
	m := map[string]bool{}
	for _, pkgs := range servicesByPort {
		for _, p := range pkgs {
			m[p] = true
		}
	}
	for _, libs := range libraries {
		for _, l := range libs {
			m[l] = true
		}
	}
	// Libraries a runtime pulls in for TLS, HTTP and data formats.
	// The Go standard library and modules that serve or parse network
	// traffic in Go programs.
	for _, l := range []string{"stdlib", "golang.org/x/net", "golang.org/x/crypto", "google.golang.org/grpc", "github.com/quic-go/quic-go", "golang.org/x/net/http2"} {
		m[l] = true
	}
	for _, l := range []string{"curl", "gnutls28", "nghttp2", "libssh", "libssh2", "expat", "libxml2", "zlib", "openssl", "openssl3", "krb5", "libtasn1-6", "glibc", "musl", "busybox", "python3", "nodejs", "perl"} {
		m[l] = true
	}
	return m
}()
