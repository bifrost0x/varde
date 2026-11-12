// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestLoadAgent(t *testing.T) {
	base := map[string]string{"VARDE_SERVER_URL": "https://varde.lan:8443"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cfg, err := LoadAgent(lookupFrom(base))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoUpdate || cfg.DockerHost != "tcp://socket-proxy:2375" {
		t.Fatalf("defaults: %+v", cfg)
	}
	// A host without Docker still has an inventory to report.
	cfg, err = LoadAgent(lookupFrom(with("VARDE_DOCKER_HOST", "off", "VARDE_AGENT_AUTO_UPDATE", "false")))
	if err != nil || cfg.DockerHost != DockerHostOff || cfg.AutoUpdate {
		t.Fatalf("off: %+v %v", cfg, err)
	}
	cfg, err = LoadAgent(lookupFrom(with("VARDE_DOCKER_HOST", "unix:///var/run/docker.sock", "VARDE_ALLOW_DIRECT_SOCKET", "true")))
	if err != nil || cfg.DockerHost != "unix:///var/run/docker.sock" {
		t.Fatalf("direct socket: %+v %v", cfg, err)
	}
	for _, bad := range []map[string]string{
		with("VARDE_DOCKER_HOST", "unix:///var/run/docker.sock"),
		with("VARDE_AGENT_AUTO_UPDATE", "sometimes"),
		with("VARDE_SERVER_URL", "http://varde.lan:8443"),
		{},
	} {
		if _, err := LoadAgent(lookupFrom(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestAgentBinaryDir(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{"VARDE_AGENT_BINARY_DIR": "/opt/varde/agent"}))
	if err != nil || cfg.AgentBinaryDir != "/opt/varde/agent" {
		t.Fatalf("%+v %v", cfg.AgentBinaryDir, err)
	}
	if _, err := Load(lookupFrom(map[string]string{"VARDE_AGENT_BINARY_DIR": "agent"})); err == nil || !strings.Contains(err.Error(), "AGENT_BINARY_DIR") {
		t.Fatalf("relative path: %v", err)
	}
}
