// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"strings"
	"testing"
)

func TestProgram(t *testing.T) {
	cases := []struct {
		want    string
		command []string
	}{
		{"nginx", []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}},
		{"python", []string{"tini", "--", "python", "-m", "immich_ml"}},
		{"node", []string{"/usr/bin/dumb-init", "--", "node", "server.js"}},
		{"caddy", []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile"}},
		{"httpd", []string{"sh", "-c", "exec httpd -DFOREGROUND"}},
		{"gunicorn", []string{"/entrypoint.sh", "gunicorn", "app:app"}},
		{"init", []string{"/init"}},
		{"", []string{"/start.sh"}},
		{"", nil},
	}
	for _, c := range cases {
		if got := Program(c.command); got != c.want {
			t.Errorf("Program(%q) = %q, want %q", c.command, got, c.want)
		}
	}
}

func TestComponentOf(t *testing.T) {
	nginx := []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}
	ml := []string{"tini", "--", "python", "-m", "immich_ml"}
	tool := []string{"/usr/local/bin/sometool", "--serve"}
	cases := []struct {
		name    string
		pkg     string
		command []string
		exposed bool
		want    Reach
	}{
		{"the program of an exposed container", "nginx", nginx, true, Served},
		{"a library of a known server", "openssl", nginx, true, Served},
		{"a versioned library", "openssl3", nginx, true, Served},
		{"a bundled tool is only in the image", "busybox", nginx, true, InImage},
		{"a bundled library no server loads", "libtiff", nginx, true, InImage},
		{"not exposed: never served", "nginx", nginx, false, InImage},
		{"the python runtime of a python server", "python3.11", ml, true, Served},
		{"unknown program: libraries stay in the image", "openssl", tool, true, InImage},
		{"no command known: in the image", "openssl", nil, true, InImage},
	}
	for _, c := range cases {
		if got := ComponentOf(c.pkg, c.command, c.exposed); got.Reach != c.want {
			t.Errorf("%s: %q = %s, want %s", c.name, c.pkg, got.Reach, c.want)
		}
	}
}

// What an inventory keeps of a command never holds an argument.
func TestCommandPrefixDropsArguments(t *testing.T) {
	cases := []struct {
		command, want []string
	}{
		{[]string{"redis-server", "--requirepass", "s3cret"}, []string{"redis-server"}},
		{[]string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}, []string{"/docker-entrypoint.sh", "nginx"}},
		{[]string{"tini", "--", "python", "-m", "app", "--token", "abc"}, []string{"tini", "python"}},
		{[]string{"sh", "-c", "exec httpd --password=x -DFOREGROUND"}, []string{"sh", "exec", "httpd"}},
		{[]string{"/init"}, []string{"/init"}},
		{[]string{"/start.sh"}, []string{"/start.sh"}},
	}
	for _, c := range cases {
		got := CommandPrefix(c.command)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("CommandPrefix(%q) = %q, want %q", c.command, got, c.want)
		}
		if Program(got) != Program(c.command) {
			t.Errorf("prefix of %q names %q, the command %q", c.command, Program(got), Program(c.command))
		}
	}
}
