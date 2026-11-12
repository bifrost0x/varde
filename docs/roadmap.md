# Roadmap

What v1 does not do yet, what comes next, and the known limitations of the current state. The
history of what was built is in `CHANGELOG.md`; design decisions are in `docs/adr/`.

## Known limitations

- Advisory mode defaults to `direct`: the central feed is not published yet, so there is no
  embedded production trust root. Feed mode works with a self-hosted feed and
  `VARDE_FEED_ROOT_FILE` (`docs/feed-trust.md`).
- Notification channels are configured through environment variables only; the settings page shows
  them read-only, so channel secrets never pass through the UI.
- Resolved findings are reported in the weekly digest only, not in a message of their own.
- Varde installs agents on Linux hosts with systemd or OpenRC, for linux/amd64 and linux/arm64
  (ADR 0031); elsewhere the agent is run by hand.
- Every installed package of hosts and container images is checked against its distribution's
  security data in direct mode (ADR 0032, ADR 0033); issues without a fix yet are counted for
  hosts, not reported, and feed mode checks catalog apps only.
- Agents send a full snapshot when something changed and a heartbeat otherwise, instead of diffs
  (ADR 0019).
- Exposure reads Traefik labels and the routes of connected reverse proxies (Traefik API, Nginx
  Proxy Manager); other proxies and router port forwards stay invisible.
- Distribution packages are compared with their distribution's security data on Debian, Ubuntu,
  Alpine, AlmaLinux, Rocky Linux and openSUSE Leap only, and only with `DIRECT_OSV` on; RHEL and
  Fedora packages stay not comparable (ADR 0028).
- Attack paths are a model (ADR 0034): router port forwards and firewalls are invisible, the
  port-to-package map and library lists are heuristics, and a path through a library is marked
  indirect. Without listening sockets (agents, SSH inventories) a host's findings stay unclear.
- App dependencies are read in container images only, and only Go programs (from the image's
  entrypoint or command) and npm lock files next to the app's `package.json`; Python, Java and
  Rust dependencies, binaries on hosts outside the package manager, snaps and flatpaks are not
  checked. rpm databases before rpm 4.16 (Berkeley DB, NDB) are not read.
- Device firmware is reported only where a controller says an update is available (UniFi); no
  advisory feed covers it.

## Direction: agentless first

Varde works without agents. Installed once on a Docker host, it discovers what runs in the networks
the user allows and records the inventory through the official integration interfaces of each
platform (Proxmox VE API, Docker Engine API over SSH or TLS, and the APIs of common homelab
services). The agent stays an optional collector for hosts Varde cannot reach, for example in
another VLAN or behind a VPN. ADR 0020 records the decision.

- **Official interfaces only.** Each integration uses what the platform documents for this
  purpose, with the least privilege it offers (read-only API tokens, restricted SSH keys).
- **Modular.** Every integration can be switched on and off on its own; nothing runs unless the
  user enabled it.
- **Guided onboarding.** Each integration comes with a setup flow that says exactly what to create
  on the other side (token, role, key line), checks the connection and explains failures in plain
  words.
- **Product tour.** A guided tour through the main pages, as in WebSSH.

## Stages

Recognition first: alerts are only worth something when the inventory is right. A stage starts when
the acceptance of the previous one is met; `make eval` measures it (ADR 0023).

1. **Discovery (in progress).** Done: relations (guest to node), stacks and mounts, all LXC
   containers of a node through one key, ranked next steps, Traefik, Nginx Proxy Manager, Fritz!Box
   and OPNsense with read-only credentials. Open: Pi-hole, AdGuard Home, Caddy, Docker over TLS and
   Podman, each blocked on a narrow credential or a testable interface (ADR 0024); restart policy
   (needs a per-container inspect). Acceptance: the lab without duplicates and with correct
   relations; measured in the corpus, still to be confirmed on a real Proxmox cluster.
2. **Versions (in progress).** Done: floating tags through the registry, apps derived from source
   labels (ADR 0025), package databases and app manifests of images with dpkg/rpm/apk comparison
   (ADR 0026), container drift (ADR 0027); corpus coverage 0.935. Go build information was measured
   and not adopted (mostly `(devel)`). Open: Python metadata, a central digest index in the feed.
   Acceptance: version coverage target in the corpus.
3. **Distribution advisories and library (in progress).** Done: Debian, Ubuntu and Alpine security
   data, AlmaLinux, Rocky Linux and openSUSE Leap notices through osv.dev with the dpkg, apk and
   rpm order, vendor builds left out, OpenVEX export, nginx in the catalog (ADR 0028); in the
   corpus, patched distribution packages yield no false findings; twelve more verified catalog
   entries with corpus cases. Open: RHEL (data split by repository). Acceptance: patched
   distribution packages yield no false findings.
4. **Remediation.** Done: the release tag that fixes a container, from the registry's tag list and
   in the running tag's form, Compose lines and commands, end of life from endoflife.date, Discord
   and Telegram, the product tour (ADR 0029); integration management on the network page.

## Later

- More integrations: Docker over TLS, Portainer, the Caddy API, Home Assistant.
- Dependencies beyond Go and npm (Python, Java, Rust), programs on hosts outside the package
  manager, snaps and flatpaks; rpm databases before rpm 4.16.
- Roles (read-only users) and notification channels configured in the UI.
- v2: the central feed pipeline (`bifrost0x/varde-feed`) and feed mode as the default.
