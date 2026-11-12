// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"time"
)

// Agent is the configuration of `varde agent`.
type Agent struct {
	LogLevel  slog.Level
	LogFormat string
	// DataDir holds the agent key, certificate and state.
	DataDir string
	// ServerURL is the server's agent listener, https://host:8443.
	ServerURL string
	// EnrollToken is needed only for the first start.
	EnrollToken Secret
	// DockerHost is the Docker API to read containers from, or "off" on a
	// host without Docker: the agent then reports the host inventory only.
	DockerHost        string
	AllowDirectSocket bool
	// Name is the host name shown in the UI; empty means the Docker host
	// name, or the system's host name without Docker.
	Name string
	// AutoUpdate lets the agent replace its own binary with the one the
	// server ships, when it may write it.
	AutoUpdate bool
	// Interval between full checks and heartbeats.
	Interval time.Duration
}

// LoadAgent reads the agent configuration.
func LoadAgent(lookup LookupFunc) (Agent, error) {
	l := loader{lookup: lookup, set: map[string]bool{}}
	cfg := Agent{
		LogLevel: slog.LevelInfo, LogFormat: "json", DataDir: "/data",
		DockerHost: "tcp://socket-proxy:2375", Interval: 15 * time.Minute, AutoUpdate: true,
	}
	if v, ok := l.get("LOG_LEVEL"); ok {
		lvl, err := parseLevel(v)
		if err != nil {
			l.fail("LOG_LEVEL", err)
		}
		cfg.LogLevel = lvl
	}
	if v, ok := l.get("LOG_FORMAT"); ok {
		switch v {
		case "json", "text":
			cfg.LogFormat = v
		default:
			l.fail("LOG_FORMAT", fmt.Errorf("must be json or text, got %q", v))
		}
	}
	l.str("DATA_DIR", &cfg.DataDir)
	if !filepath.IsAbs(cfg.DataDir) {
		l.fail("DATA_DIR", fmt.Errorf("must be an absolute path, got %q", cfg.DataDir))
	}
	l.str("SERVER_URL", &cfg.ServerURL)
	if u, err := url.Parse(cfg.ServerURL); cfg.ServerURL == "" {
		l.fail("SERVER_URL", errors.New("required, e.g. https://varde.lan:8443"))
	} else if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		l.fail("SERVER_URL", fmt.Errorf("must be https://host:port without path, got %q", cfg.ServerURL))
	}
	l.secret("ENROLL_TOKEN", &cfg.EnrollToken)
	l.str("DOCKER_HOST", &cfg.DockerHost)
	l.boolean("ALLOW_DIRECT_SOCKET", &cfg.AllowDirectSocket)
	if cfg.DockerHost != DockerHostOff {
		if err := validateDockerHost(cfg.DockerHost, cfg.AllowDirectSocket); err != nil {
			l.fail("DOCKER_HOST", err)
		}
	}
	l.boolean("AGENT_AUTO_UPDATE", &cfg.AutoUpdate)
	l.str("AGENT_NAME", &cfg.Name)
	if len(cfg.Name) > 128 {
		l.fail("AGENT_NAME", errors.New("at most 128 characters"))
	}
	l.duration("AGENT_INTERVAL", &cfg.Interval, time.Minute)
	if cfg.Interval > 24*time.Hour {
		l.fail("AGENT_INTERVAL", errors.New("at most 24h"))
	}
	if len(l.errs) > 0 {
		return Agent{}, errors.Join(l.errs...)
	}
	return cfg, nil
}
