// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bifrost0x/varde/internal/agent"
	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/config"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/inventory/docker"
)

func runAgent(stderr io.Writer) int {
	cfg, err := config.LoadAgent(os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: invalid configuration:\n%v\n", err)
		return 1
	}
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	var logger *slog.Logger
	if cfg.LogFormat == "text" {
		logger = slog.New(slog.NewTextHandler(stderr, opts))
	} else {
		logger = slog.New(slog.NewJSONHandler(stderr, opts))
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := agentMain(ctx, cfg, logger, defaultSocketPath); err != nil {
		logger.Error("agent stopped with error", "err", err)
		return 1
	}
	return 0
}

func agentMain(ctx context.Context, cfg config.Agent, logger *slog.Logger, socketPath string) error {
	var collector inventory.Collector = agent.HostCollector{}
	var client *docker.Client
	if cfg.DockerHost != config.DockerHostOff {
		if err := checkDirectSocket(socketPath, cfg.AllowDirectSocket, logger); err != nil {
			return err
		}
		var err error
		if client, err = docker.New(cfg.DockerHost); err != nil {
			return err
		}
	}
	a, err := agent.New(cfg, logger)
	if err != nil {
		return err
	}
	if client != nil {
		c := docker.NewCollector(client, logger)
		// The images' package databases, when the server asks for them.
		c.Packages = a.PackageReader()
		collector = c
	}
	a.ReadInventory = agent.RunInventory
	if cfg.AutoUpdate {
		exe, err := os.Executable()
		if err == nil {
			err = a.EnableSelfUpdate(exe)
		}
		if err != nil {
			// In the container image the binary is read-only: updates
			// come with the image there.
			logger.Info("self-update off", "reason", err)
		}
	}
	logger.Info("agent starting", "server", cfg.ServerURL, "interval", cfg.Interval, "version", buildinfo.Version,
		"docker", cfg.DockerHost != config.DockerHostOff)
	a.Run(ctx, collector)
	if a.Updated() {
		// The supervisor (systemd, OpenRC) starts the new binary.
		logger.Info("agent stopped to start the updated binary")
	}
	return nil
}

// runAgentHealthcheck succeeds when the agent delivered a report recently.
func runAgentHealthcheck(stderr io.Writer) int {
	cfg, err := config.LoadAgent(os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: invalid configuration:\n%v\n", err)
		return 1
	}
	if err := agent.Healthy(cfg, time.Now()); err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: unhealthy: %v\n", err)
		return 1
	}
	return 0
}
