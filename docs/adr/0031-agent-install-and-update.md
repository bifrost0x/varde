# 0031 The agent reads the full host inventory, is installed by Varde and updates itself

Status: Accepted

## Context
Agentless inventory (ADR 0030) depends on what each platform lets Varde read: a key line per host
for packages, the Proxmox node key for guests, the QEMU guest agent for VMs, Docker over SSH for
containers. Each path has its own setup, its own gaps (no image labels through the guest agent, VMs
without agent) and its own failure modes, and none covers a host outside the allowed networks.
The existing agent (ADR 0011, ADR 0019) reported Docker containers only and had to be deployed by
hand, with a token copied from the UI. A user who wants the complete inventory of every server and
every container, permanently, needs one way that works the same on every Linux host and keeps
working without attention.

## Decision
- **The agent reports the full host inventory.** It runs the inventory command of the SSH
  inventory (`InventoryCommand`, ADR 0030) locally with `/bin/sh` and sends its output with every
  full snapshot. The server parses it with the same parser and stores it for the agent's host
  record in one transaction that refuses revoked agents: the full package list, MAC addresses and
  machine ID (so the agent's host merges with the Proxmox guest or scanned device, ADR 0023), and
  the catalog apps among packages and services. The agent is no more trusted than a host answering
  over SSH. The inventory is read at most every half interval and is part of the snapshot hash, so
  unchanged inventories cost a heartbeat. Docker is optional: `VARDE_DOCKER_HOST=off` reports the
  host inventory only.
- **Varde installs the agent over one SSH session.** The user enters address and user, compares
  the host key fingerprint, and enters a password or private key once. Varde signs in, reads the
  platform (`uname`, `id -u`, Docker socket, init system), creates a private temporary directory,
  uploads the agent binary for the platform, a configuration with a one-time enrollment token
  (fifteen minutes) and the install script, and runs the script as root, directly or with sudo
  (the password on stdin). Nothing secret is on a command line. The script creates the system user
  `varde-agent` without a login, installs the agent to `/var/lib/varde-agent` (owned by that user,
  so it can update itself), its configuration to `/etc/varde-agent.env` (root, readable by the
  group) and a hardened systemd unit or an OpenRC service, starts it and removes the temporary
  directory. Docker access is the user's choice and puts the user into the `docker` group. The
  credentials are used for this session only and never stored or logged.
- **The agent follows the server's version.** The image ships the agent for linux/amd64 and
  linux/arm64 (`VARDE_AGENT_BINARY_DIR`; on Linux the server's own binary is one of them). Every
  report answer names the binary for the agent's platform by SHA-256. When it differs from the
  running binary and the agent may write it, the agent downloads it from the agent listener over
  the pinned mTLS connection, checks the checksum and that it starts (`varde version`), replaces
  itself atomically and exits; systemd or OpenRC starts the new one. The agent in the container
  image cannot write its binary and updates with the image. `VARDE_AGENT_AUTO_UPDATE=false`
  switches this off.

## Consequences
- One agent gives the same complete inventory on every Linux host, inside or outside the allowed
  networks, including Docker containers with their labels, without key lines per host.
- **The server can now run code on agent hosts.** The update channel means whoever controls the
  Varde server (or its CA key) can push a binary that agents run as `varde-agent`, which is root
  on hosts where the user granted Docker access. Before, a compromised server could only read.
  The binary comes only from the agent listener over the pinned connection, checked against the
  checksum in the authenticated report answer; there is no separate signing key, since the
  server that would hold it is the same trust anchor. The threat model says so; a user who does
  not accept it sets `VARDE_AGENT_AUTO_UPDATE=false`.
- The installation needs root or sudo once. Varde never keeps these credentials; the agent itself
  runs without privileges unless Docker access was chosen.
- An older server refuses reports of a newer agent (strict decoding); servers are updated first,
  and agents installed by Varde always follow the server.
- Hosts without systemd or OpenRC, and platforms other than linux/amd64 and linux/arm64, are not
  installed by Varde; the agent can still be run by hand there.
