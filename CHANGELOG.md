# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Data package (ADR 0039): with a trust root, an installation reads its advisories, the KEV list,
  EPSS scores and the recognition table from one signed package the project builds once a day,
  and asks no other source about its apps. Settings › Data package shows what is in use and
  updates it on demand; asking GitHub about apps the package does not cover is a switch, off by
  default (`VARDE_DIRECT_QUERIES`). Releases carry no trust root yet, so nothing changes until
  the key ceremony of `docs/data-package.md`. The package is built by `cmd/packagebuilder` and a
  daily workflow that stays idle until it is switched on; `cmd/vardekeys` makes the keys offline.
- Recognition beyond the catalog (ADR 0038): a first-party index of image repositories and the
  projects that publish them is built into the binary, so apps without a catalog entry are
  recognised and checked against their project's advisories without any download. The uplink
  switch under Settings changes between the free data and a subscription at runtime.

- Wider detection (ADR 0036):
  - Python, PHP, Ruby, .NET and Java packages in images, and Rust programs built with
    cargo-auditable, are checked against their OSV ecosystems, each in its own version order (image
    reader format 3; migration 0028 marks reads that stopped at a size bound).
  - Wolfi, Chainguard, openSUSE Tumbleweed and Red Hat Enterprise Linux / UBI images and hosts are
    checked against their distribution data.
  - Integrations for Synology DSM, QNAP, TrueNAS, Unraid and Home Assistant OS read the system's
    own version and check it against advisories; the scan offers them on devices it recognises.
  - Scans ask every address by mDNS and SSDP and name printers, speakers and smart home devices by
    what they announce; with `VARDE_SNMP_COMMUNITY` or an SNMP v3 user they read the system
    description of switches, UPS, printers and NAS.
  - Docker Engine and containerd from Docker's own repositories are checked against their
    advisories; FRITZ!OS and the firmware of each UniFi device are recorded per system.

- History (ADR 0035): every finding records when it was opened, reopened and resolved, and why it
  ended: an update (with the version before and after), the package removed, the container or
  system gone, or the advisory no longer applying (migration 0027; existing findings start with
  their known dates). "History" under Findings shows what was fixed per period and system, the
  median time to fix per priority, what has waited longest and a timeline; each finding shows its
  own history next to the actions taken on it. The page prints as a report and exports as CSV.
- Findings are grouped by what fixes them: one card per container (pull a newer image and recreate
  it), per system's packages (install the updates, with the command) or per app, most urgent
  first. Grouping by package and one row per advisory remain. The overview leads with the number
  of urgent updates to do and shows them right below the counters; "KEV" reads "exploited".

- Installing the agent tests right away whether the host reaches the server's agent port
  (`varde check-server`) and names the reason when it does not, instead of a silent "not
  connected". The guide keeps offering the hosts whose agent did not get through, also after
  another host's agent connected. The removal commands for the agent say that they run as root.

- `varde backup <file>` writes a consistent backup of the database, the agent CA and the keys
  while the server runs; `varde restore <file>` unpacks one into an empty data directory.
- `VARDE_HOST_ADDRESS` names the machine Varde runs on in the network: it ties "this host" to its
  scan record and is the server address agents are given.
- A suppression can be lifted on the finding's page. An advisory source that keeps failing for two
  days becomes a notice.
- Distribution data is read the way each distribution publishes it: binary package names on
  AlmaLinux, Rocky Linux and openSUSE, the kernel at the running version (not headers or
  `linux-libc-dev`, which are left out of images), source versions of Debian packages, Ubuntu Pro
  records for LTS releases past standard support, notices where a release has no per-CVE records
  (Debian 11), and Raspberry Pi OS as Debian. Distroless images are read from `status.d`; images
  whose package database Varde cannot read (rpm before 4.16) say so instead of looking clean.

- Attack paths (ADR 0034): every analysis builds the ways an attacker gets in, from the internet
  (proxy routes under public domains) or the LAN (scanned and listening services, published
  ports), through a flaw in a reachable service or a library it uses, out of a container
  (privileged, Docker socket, host root, shared kernel), to root, from an LXC guest to its Proxmox
  node, to containers on the same Docker network and to the next machine. "Attack paths" shows
  each path step by step with the fix that cuts it; the overview shows the top three.
- Background noise: findings no path uses, with the reason (physical access only, a local flaw on a
  machine no path reaches, a container nothing reaches, a package no listening service uses), have
  their own page and stay at P3 (P2 when known exploited). Findings on a path from the internet
  become P1 when known exploited or CVSS 7+, amplifiers and LAN paths at least P2. Findings carry
  a badge and a filter; notifications name the path (migration 0022).
- The inventory command reads the sockets a host listens on, in new sections older readers skip
  (migration 0021); the Docker collector reads the settings that decide what a
  container can do on its host. Distribution records without a severity take the CVSS vector of
  their CVE, so the attack vector of package findings is known.
- Container images on AlmaLinux, Rocky Linux and openSUSE (rpm 4.16+ SQLite database) have their
  packages checked; the database is read by a bounded reader of the file format, never by SQL.
- The dependencies of apps in container images are checked: the Go modules and toolchain compiled
  into the program the image runs (read as a stream, only the build information is kept) and the
  npm packages of the app's `package-lock.json`, against the Go vulnerability database and GitHub's
  npm advisories on osv.dev, including known malicious npm packages.
- Images on `ghcr.io/<owner>/<repo>` without a source label get a derived catalog entry like
  labelled ones; a guessed repository that does not exist is no failing source.
- UniFi devices with a newer firmware on offer are listed as a notice, with model, address and
  version.

- Varde tells when a host's updates wait for a restart: a newer kernel is installed than the one
  running (also Proxmox kernels), or Debian's or Ubuntu's restart note is set. The systems list,
  the system's page and the overview show it (inventory command version 3, migration 0020).
- Issues in the packages of a container's image that no newer image fixes yet are counted on the
  container ("without fix"), like those of host packages.
- The packages of container images are checked against their distribution's security data and
  reported on the container, with a newer image as the action (ADR 0033). Agents read the images of
  their own containers when "Read the package lists of images" is on; the server keeps an agent's
  record only for images its own containers use and never over another source's (migration 0019).
- Every installed package of every host is checked against its distribution's security data
  (Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, openSUSE Leap), not only those of catalog apps:
  each update that fixes a vulnerability is a finding with the version that fixes it. osv.dev
  evaluates the installed versions in batches; only affecting records are downloaded and kept until
  they change. Debian's "unimportant" issues are dropped; issues without a fix yet are counted per
  package on the system's page ("without fix", migration 0018) and become findings once an update
  fixes them. Switched with the osv.dev source, which the guide now asks for (ADR 0032).
- UniFi integration (UniFi Network 9.0+): the client list with address, MAC and name, through the
  official integration API with a view-only API key. Devices the scan recognises as UniFi OS,
  OPNsense or Fritz!Box offer their connection; Portainer hosts point to the agent.
- Project skeleton: `varde server` with `/healthz`, `varde healthcheck`, `varde version`.
- Hardened container image (distroless static, non-root, read-only compatible).
- CI: lint, race tests, fuzz smoke, govulncheck, license headers, image size budget and smoke test.
- Architecture decision records, threat model draft, brand assets.
- Local Docker inventory through a read-only socket proxy, event-driven with periodic resync.
- SQLite state store with embedded migrations.
- `/readyz`, `/api/v1/hosts`, `/api/v1/workloads` with manual entries (static bearer token).
- Refusal to start with a directly mounted Docker socket unless explicitly allowed.
- App catalog with 33 verified seed entries, strict loader and local overrides (`VARDE_CATALOG_DIR`).
- Identification of containers and manual entries, with version resolution from labels and tags.
- Direct-mode advisory sources: GitHub repository advisories, CISA KEV, FIRST EPSS; OSV and NVD opt-in.
- Matching engine with alias deduplication, evidence and fixed versions; `/api/v1/findings`, `/api/v1/sources`.
- Hardened outbound HTTP client with optional egress allowlist and custom CA bundle.
- Exposure detection (label, Traefik routes, port bindings) and P1/P2/P3 prioritisation.
- Finding lifecycle (acknowledge, snooze, suppress with reason and expiry) with audit log.
- Notifications via ntfy, Gotify, signed webhook and SMTP; P1 immediately, daily and weekly digests.
- Web UI: overview, findings with lifecycle actions, inventory with manual entries, coverage with
  gap suggestions, hosts, sources, settings. Dark and light theme, works at phone width.
- Accounts: one-time setup token, argon2id passwords, server-side sessions, CSRF protection,
  login throttling, trusted-proxy handling, strict Content Security Policy.
- API tokens with `read` or `write` scope; `GET /api/v1/status`, `POST /api/v1/scan`;
  OpenAPI 3.1 description in `docs/api/openapi.yaml`.
- Runtime settings (exposure domains, digest schedule, opt-in sources, policy thresholds) editable
  in the UI; environment variables take precedence and lock the field.
- `/metrics` in Prometheus text format (authenticated).
- `varde agent` for further Docker hosts: one-time enrollment tokens, internal CA, mTLS push on a
  separate listener (`VARDE_AGENT_LISTEN_ADDR`, default `:8443`), certificate pinning, immediate
  revocation, automatic rotation, `varde healthcheck agent`.
- Hosts that stop reporting and public routes Varde cannot assess are shown as blind spots and
  included once in the daily digest.
- Example deployments in `deploy/`.
- Signed central feed client (`VARDE_MODE=feed|hybrid`): Ed25519 trust root with rotation chain,
  rollback and freeze protection, content-addressed zstd blobs with size limits, staged atomic
  installation, mirrors and air-gapped import from a directory or tarball, stale-feed notice.
  The catalog can now be replaced at runtime. `cmd/feedbuilder` (development only, `-tags feeddev`).
- `varde reset-password <user>` for locked-out installations (run inside the container).
- Release workflow for signed multi-arch images with SBOM and provenance (runs only on version tags).
- Documentation: architecture, performance measurements, release procedure, security review.
- Findings grouped by app and running version, with one target version that fixes them together.
  The target prefers the running release line; a new major version is flagged, with the best
  update on the current line shown next to it. The flat view stays available.
- The overview separates new findings from acknowledged ones; the top bar beacon and the counters
  follow new findings only.
- Databases, Docker socket proxies, update helpers and Varde itself no longer count as coverage
  gaps; any unidentified image can be marked as "not an app" (audited, reversible).
- Plainer wording for findings Varde cannot confirm and for unknown versions, each with the next
  step.
- Network page: allow private ranges, scan them for hosts and services, and see what Varde reads
  each device as. Intercepted ports (a router redirecting DNS) are detected and ignored.
- Agentless integrations through official interfaces: the Proxmox VE API with a read-only token and a
  pinned certificate (nodes, VMs, containers with addresses), and Docker hosts through the Docker
  Engine API over SSH with a key restricted to `docker system dial-stdio`. Each can be switched on
  and off; agents remain optional.

### Fixed

- A container recreated under the same name (`docker compose up -d` after a pull) keeps its
  findings: they were all resolved and opened again, so the update's fixes could not be told
  apart, acknowledgements were lost and urgent findings notified again.

- A network scan no longer loses hosts from one run to the next: attempts that got no answer are
  tried again, slower and with a longer timeout, and the default rate is lower (100 attempts per
  second, 32 at a time), which a UniFi router and Docker Desktop over WLAN dropped at 300. A device
  is removed only after it missed two scans in a row and is marked after the first (migration
  0025).
- Image package reads carry a reader format: images read by an older reader are read again after
  an upgrade instead of waiting a week (migration 0024). Go programs in `/usr/local/bin` (gosu, for
  example) are read as well.
- A Go or npm advisory naming two modules of one program gives one finding per module, each with
  its own update, instead of one finding whose update fixed only one of them. The findings table
  is rebuilt without its (workload, advisory) uniqueness for this (migration 0026, every row kept);
  an existing Go or npm finding moves to its module's ID with its state, instead of being resolved
  and opened again after the upgrade.
- SQLite keeps temporary data in memory: in the read-only container it found no temp directory and
  failed with "disk I/O error" on larger sorts and table rebuilds.
- A Debian notice followed by a second notice for the same package keeps the package affected
  until the second fix is installed.
- The action for a package of an image names the package: "a newer image whose brotli is 1.2.8 or
  later", not "a newer image with 1.2.8", which read like an image version.
- The UniFi setup no longer claims that a View Only admin can create an API key: UniFi has no
  read-only keys and lets only an admin with full rights create one, and the place of the setting
  differs between Network versions.
- Buttons in the device list ("Connect Proxmox", "Install the agent") were drawn as empty white
  boxes.

### Security

- Built with Go 1.27.4, which fixes GO-2026-6859 in `net/http`.

- Login, setup, password change and agent enrollment reserve throttle attempts atomically; waiting
  for password hashing is bounded.
- Stricter validation of the return path after login; the return path works again.
- Feed manifests bound each blob's declared size; the API limits request bodies before
  authorisation; agent snapshots are refused once the host is revoked; development feed roots need
  `VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true`.
