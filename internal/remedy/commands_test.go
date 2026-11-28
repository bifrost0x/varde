// SPDX-License-Identifier: Apache-2.0

package remedy

import (
	"testing"

	"github.com/bifrost0x/varde/internal/inventory"
)

func composeOf(labels map[string]string) *Compose {
	return ComposeOf(&inventory.Container{Labels: labels})
}

func TestComposeCommands(t *testing.T) {
	cases := []struct {
		name          string
		labels        map[string]string
		pull, rebuild string
	}{
		{
			name:   "without directory: as before",
			labels: map[string]string{labelProject: "immich", labelService: "immich-server"},
			pull:   "docker compose pull 'immich-server' && docker compose up -d 'immich-server'",
		},
		{
			// Named also when it is the default: Compose would otherwise
			// add a compose.override.yml the project was started without.
			name: "a single default file is named",
			labels: map[string]string{labelProject: "immich", labelService: "immich-server",
				labelWorkingDir: "/srv/immich", labelConfigFiles: "/srv/immich/docker-compose.yml"},
			pull:    "cd '/srv/immich' && docker compose -f 'docker-compose.yml' pull 'immich-server' && docker compose -f 'docker-compose.yml' up -d 'immich-server'",
			rebuild: "cd '/srv/immich' && docker compose -f 'docker-compose.yml' build --pull --no-cache 'immich-server' && docker compose -f 'docker-compose.yml' up -d 'immich-server'",
		},
		{
			name: "two files and a project name of its own",
			labels: map[string]string{labelProject: "webssh-rc1", labelService: "webssh",
				labelWorkingDir: "/home/x/rc1-hosting", labelConfigFiles: "/home/x/rc1-hosting/compose.yml,/home/x/rc1-hosting/compose.tls.yml"},
			pull: "cd '/home/x/rc1-hosting' && docker compose -p 'webssh-rc1' -f 'compose.yml' -f 'compose.tls.yml' pull 'webssh' && " +
				"docker compose -p 'webssh-rc1' -f 'compose.yml' -f 'compose.tls.yml' up -d 'webssh'",
		},
		{
			name: "an environment file other than .env",
			labels: map[string]string{labelProject: "webssh-lab", labelService: "ssh-bastion",
				labelWorkingDir: "/srv/lab", labelConfigFiles: "/srv/lab/compose.yml", labelEnvFiles: "/srv/lab/lab.env"},
			pull: "cd '/srv/lab' && docker compose -p 'webssh-lab' -f 'compose.yml' --env-file 'lab.env' pull 'ssh-bastion' && " +
				"docker compose -p 'webssh-lab' -f 'compose.yml' --env-file 'lab.env' up -d 'ssh-bastion'",
		},
		{
			name: "the default .env is read without naming it",
			labels: map[string]string{labelProject: "app", labelService: "web",
				labelWorkingDir: "/srv/app", labelConfigFiles: "/srv/app/compose.yml", labelEnvFiles: "/srv/app/.env"},
			pull: "cd '/srv/app' && docker compose -f 'compose.yml' pull 'web' && docker compose -f 'compose.yml' up -d 'web'",
		},
		{
			name: "a file outside the directory keeps its path",
			labels: map[string]string{labelProject: "media", labelService: "jellyfin",
				labelWorkingDir: "/opt/Media", labelConfigFiles: "/opt/Media/stack.yaml,/etc/compose/override.yaml"},
			pull: "cd '/opt/Media' && docker compose -f 'stack.yaml' -f '/etc/compose/override.yaml' pull 'jellyfin' && " +
				"docker compose -f 'stack.yaml' -f '/etc/compose/override.yaml' up -d 'jellyfin'",
		},
	}
	for _, c := range cases {
		got := composeOf(c.labels)
		if got == nil {
			t.Fatalf("%s: no compose", c.name)
		}
		if p := got.Pull(); p != c.pull {
			t.Errorf("%s: Pull\n got %s\nwant %s", c.name, p, c.pull)
		}
		if c.rebuild != "" && got.Rebuild() != c.rebuild {
			t.Errorf("%s: Rebuild\n got %s\nwant %s", c.name, got.Rebuild(), c.rebuild)
		}
		if got.Portainer != "" {
			t.Errorf("%s: not a Portainer stack", c.name)
		}
	}
}

func TestPortainerAndUnraid(t *testing.T) {
	c := composeOf(map[string]string{labelProject: "paperless", labelService: "webserver",
		labelWorkingDir: "/data/compose/12", labelConfigFiles: "/data/compose/12/docker-compose.yml"})
	if c == nil || c.Portainer != "12" {
		t.Fatalf("Portainer stack not recognised: %+v", c)
	}
	if c := composeOf(map[string]string{labelProject: "x", labelService: "y", labelWorkingDir: "/data/compose-files/12"}); c.Portainer != "" {
		t.Error("a directory that only looks similar is no Portainer stack")
	}
	if !Unraid(&inventory.Container{Labels: map[string]string{"net.unraid.docker.managed": "dockerman"}}) || Unraid(&inventory.Container{}) || Unraid(nil) {
		t.Error("Unraid")
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("shellQuote = %s", got)
	}
	if defaultProject("/home/x/My Stack.v2/") != "mystackv2" || defaultProject(`C:\stacks\Web`) != "web" {
		t.Error("defaultProject")
	}
}

func TestPackageCommand(t *testing.T) {
	cases := []struct {
		release string
		names   []string
		want    string
	}{
		{"debian-12", []string{"openssl", "libssl3", "openssl"}, "apt-get update && apt-get install --only-upgrade libssl3 openssl"},
		{"ubuntu-24.04", []string{"curl"}, "apt-get update && apt-get install --only-upgrade curl"},
		{"alpine-3.22.1", []string{"libcrypto3"}, "apk update && apk upgrade libcrypto3"},
		{"rocky-9.4", []string{"openssl-libs"}, "dnf upgrade --refresh openssl-libs"},
		{"opensuse-leap-15.6", []string{"libopenssl3"}, "zypper refresh && zypper update libopenssl3"},
		{"fedora-40", []string{"curl"}, ""},
		// A name a package database would not hold never reaches the shell.
		{"debian-12", []string{"x; rm -rf /", "$(id)"}, ""},
		{"debian-12", []string{"x; rm -rf /", "bash"}, "apt-get update && apt-get install --only-upgrade bash"},
	}
	for _, c := range cases {
		if got := PackageCommand(c.release, c.names); got != c.want {
			t.Errorf("PackageCommand(%s, %v) = %q, want %q", c.release, c.names, got, c.want)
		}
	}
	cmd := PackageCommand("debian-12", []string{"curl"})
	if got := AsRoot(cmd); got != "sudo sh -c 'apt-get update && apt-get install --only-upgrade curl'" {
		t.Errorf("AsRoot = %s", got)
	}
	if got := InLXC(105, cmd); got != "pct exec 105 -- sh -c 'apt-get update && apt-get install --only-upgrade curl'" {
		t.Errorf("InLXC = %s", got)
	}
}
