// SPDX-License-Identifier: Apache-2.0

// Command varde is the Varde server, agent and healthcheck binary.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/config"
)

const shutdownTimeout = 10 * time.Second

const usage = `Usage: varde <command>

Commands:
  server        run the server (UI, API, scanning, notifications)
  agent         run as agent on a remote host and push its inventory to the server
  check-server  test whether this host reaches the server's agent port
                (VARDE_SERVER_URL), as the agent installation does
  healthcheck   probe the local server's /healthz and exit 0 if healthy
                ("healthcheck agent": succeed if the agent reported recently)
  reset-password <user>
                set a random password for an account and end its sessions
                (run where the server runs, e.g. docker exec varde /varde reset-password admin)
  backup <file> write a consistent backup of the data directory (database,
                agent CA, keys) to an absolute path while the server runs
                (docker exec varde /varde backup /data/varde-backup.tar)
  restore <file>
                unpack a backup into an empty data directory, with the
                server stopped
  version       print version information
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if strings.Join(args, " ") == "healthcheck agent" {
		return runAgentHealthcheck(stderr)
	}
	if len(args) == 2 && args[0] == "reset-password" {
		return runResetPassword(args[1], stdout, stderr) //nolint:gosec // len(args) == 2 checked above
	}
	if len(args) == 2 && args[0] == "backup" {
		return runBackup(args[1], stdout, stderr) //nolint:gosec // len(args) == 2 checked above
	}
	if len(args) == 2 && args[0] == "restore" {
		return runRestore(args[1], stdout, stderr) //nolint:gosec // len(args) == 2 checked above
	}
	if len(args) != 1 {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}

	switch args[0] {
	case "check-server":
		return runCheckServer(stdout, stderr)
	case "server":
		return runServer(stderr)
	case "agent":
		return runAgent(stderr)
	case "healthcheck":
		return runHealthcheck(stderr)
	case "version":
		_, _ = fmt.Fprintf(stdout, "%s %s (commit %s, built %s)\n",
			buildinfo.ID, buildinfo.Version, buildinfo.Commit, buildDate(buildinfo.Date))
		return 0
	case "help", "-h", "--help":
		_, _ = io.WriteString(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "varde: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runServer(stderr io.Writer) int {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "varde: invalid configuration:\n%v\n", err)
		return 1
	}
	logger := newLogger(cfg, stderr)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, cfg, logger, serverDeps{socketPath: defaultSocketPath}); err != nil {
		logger.Error("server stopped with error", "err", err)
		return 1
	}
	return 0
}

func newLogger(cfg config.Config, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// buildDate shows a build date given as Unix seconds (SOURCE_DATE_EPOCH)
// as a date; anything else as it is.
func buildDate(s string) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return s
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}
