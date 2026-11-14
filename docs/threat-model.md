# Threat model

Status: v1. Findings of the review are in `docs/security-review.md`.

## Assets

| Asset | Why it matters |
|---|---|
| Inventory (apps, versions, hosts, exposure) | A precise list of vulnerable, reachable services: an attacker's target list |
| Docker API access | Root-equivalent on the host if not restricted |
| Findings, suppressions, audit log | Tampering hides real issues or creates false trust |
| Admin credentials, sessions, API tokens | Full control over configuration and suppressions |
| Agent CA private key | Allows minting agent certificates and injecting forged inventory |
| Agent binaries and the update channel | Code that every self-updating agent runs (ADR 0031) |
| Credentials entered for an agent installation | Root or sudo on the target host, for one session |
| Integration credentials (Proxmox token secrets, Varde's SSH key) | Read access to Proxmox; Docker API access (root-equivalent) on every host that accepts the key |
| Notification secrets (ntfy/Gotify tokens, SMTP credentials, webhook HMAC key) | Abuse of the user's notification channels |
| Feed trust root (embedded public keys) and `feed_state` | Rollback or forged advisories if subverted |
| Release artefacts (image, SBOM, signatures) | Supply-chain compromise of every installation |

## Trust boundaries

1. Varde process <-> socket proxy <-> Docker daemon (local host).
2. Browser / API client <-> Varde UI/API listener (LAN, possibly via reverse proxy).
3. Agent <-> Varde agent listener (other hosts/VLANs, mTLS).
4. Varde <-> internet upstreams: feed CDN/mirrors, GitHub API, CISA KEV, FIRST EPSS, OSV.
5. Varde <-> notification endpoints (ntfy, Gotify, webhook, SMTP).
6. Catalog contributors <-> catalog repository <-> feed pipeline.
7. Contributors <-> CI <-> registries (release pipeline).
8. Varde <-> local network: discovery scans and integrations (Proxmox API, Docker over SSH).

## Attacker capabilities considered

- A1: Network attacker on the path to upstreams (MITM where TLS is broken or a CA is misissued).
- A2: Compromised CDN, mirror or upstream API returning arbitrary content.
- A3: Malicious or compromised container on the same Docker host (controls its own labels, image
  metadata, and possibly HTTP responses if probes are enabled).
- A4: Unauthenticated user on the LAN reaching the UI/API or the agent listener.
- A5: Authenticated low-privilege API token holder (`read` scope).
- A6: Malicious catalog contributor (pull requests to the catalog).
- A7: Malicious pull request to the code repository targeting CI.
- A8: Stolen agent host (has a valid agent certificate).

Out of scope: an attacker with root on the Varde host or the Docker host; compromise of the maintainer's
signing keys combined with the release pipeline (residual risk, mitigated by key separation).

## STRIDE by component

### Docker inventory (boundary 1)

| Threat | Mitigation |
|---|---|
| E: Varde compromise leads to host root via Docker API | Socket proxy allows GET on containers/images/events/info/version only; POST denied; proxy on `internal: true` network; Varde refuses a direct socket mount by default (ADR 0006) |
| T: A3 sets misleading labels (`varde.version`, `varde.exposure`, OCI labels) | Labels are evidence, shown with source; label-derived data can lower urgency only for that container; documented as a residual risk: a container can lie about itself |
| D: Event flood from the daemon | Debounce (5 s), bounded queues, resync instead of unbounded replay |
| I: Varde reads files of containers (archive endpoint) | Only fixed files (os-release and package databases), `package.json` and `package-lock.json` in the image's working directory and its parent, and the program the image configuration names are requested; other paths are refused before any request; symlinks are not followed; 16 MB per file (64 MB for an rpm database, 512 MB streamed for a program); only parsed package names and versions are stored (ADR 0026, ADR 0034) |
| D/E: A3 crafts an rpm database or a program to attack the parsers | The rpm database is read by a bounded reader of the SQLite file format (pages, depth, cells and bytes counted; no SQL engine ever opens it); Go build information is searched in a stream with a fixed window and strict header checks; both are fuzzed |
| T: A3 shapes facts to hide an attack path | A container can claim a published port is internal or understate its settings only by changing its real configuration; the paths read Docker's own inspect data. A finding is noise only with a known reason; without data it stays unclear (ADR 0034) |
| I: Varde reads the change list of containers | Only paths that carry version evidence are kept; 4 MB per list, once a day per container (ADR 0027) |
| E: An image's labels put commands into the copyable update command | Images can set any label, Compose labels included. Project and service names must follow the Compose grammar or the Compose part is dropped; the service is quoted in the command; paths are shown only when plain (absolute, no control or shell characters); nothing is ever used to access files (ADR 0029) |
| T: A3 forges its package database | Packages are evidence like labels; a disagreement with the tag is a conflict, which never produces affected findings. The record of an image serves all its containers, so it is read only from a container whose package files are unchanged against the image (change list), never from one that rewrote them (ADR 0026) |
| E: The install commands change an existing account | Pasted as root, they change only a user they create (no password, docker group for Docker); an existing account keeps its password and groups and gets only the key line; they run in a subshell and stop when the user has no home (ADR 0024) |

### UI and API (boundary 2)

| Threat | Mitigation |
|---|---|
| S: Default credentials, credential stuffing | No default credentials; one-time setup token; argon2id; per-account and per-IP throttling |
| S: Brute force against the setup token | Token is 32 random bytes, valid 24 hours, stored hashed, single use; setup is throttled per IP and closes after the first account |
| S/T: Session theft, CSRF | Random 32-byte server-side sessions stored hashed, idle 24 h / absolute 7 d, `HttpOnly`, `SameSite=Strict`, `Secure` per `VARDE_COOKIE_SECURE`, rotation on login and password change; per-session CSRF token plus `Sec-Fetch-Site` (fallback `Origin`) checks (ADR 0018) |
| D: Login flood exhausting memory | argon2id hashing serialised (64 MiB at a time), request bodies capped, throttle table bounded |
| I: Clickjacking, referrer leaks | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: same-origin`; HSTS when served over TLS |
| T: XSS through advisory titles/descriptions from upstreams | `html/template` only, upstream Markdown shown as plain text in v1, strict CSP without `unsafe-inline` |
| I: Inventory leaked to unauthenticated users | All pages and API routes authenticated except `/healthz` (no details); `/readyz` and `/metrics` without inventory data or protected |
| I: Spoofed client IP via `X-Forwarded-For` | Forwarded headers honoured only from an explicit trusted-proxy CIDR list (default none) |
| E: `read` token performs writes | Scope enforced server-side per route; tested |
| I: A5 learns credentials of integrations through the API | `/api/v1/integrations` returns name, address, health, last error and the last platform report; never the configuration (pinned keys, token IDs) or the sealed secret; tested. A `read` token does see the network map (devices, hosts, addresses), as the UI does |
| R: Suppressions hide findings without trace | Suppressions require a reason, are scoped and expiring, recorded in the audit log |

### Agent channel (boundary 3)

| Threat | Mitigation |
|---|---|
| S: Rogue agent enrolls | Single-use enrollment tokens valid one hour, stored hashed, shown once; CSR-based enrollment; enrollment throttled per IP |
| S: Agent talks to an impostor server | Token carries the CA fingerprint; the agent accepts only a chain to that CA (ADR 0019) |
| S: Forged agent certificates | CA key generated on first start, stored only under `/data` with 0600, never exported |
| T/S: A8 stolen agent pushes forged inventory for other hosts | Certificate bound to one host ID; server ignores host fields in payloads that do not match the certificate; revocation effective immediately |
| D: Oversized or high-rate pushes | Per-agent rate limit (burst 10, one request per 6 s), 32 MiB body cap with at most 16 MiB host inventory, at most 5000 workloads, strict schema decoding with unknown fields rejected |
| T: Agent injects markup or other workload kinds | Only container workloads accepted; the host inventory is parsed by the same untrusted-input parser as the SSH inventory (bounded lines, checked fields) and stored for the certificate's host only, in a transaction that refuses revoked agents; all text escaped by templates; agent fields length- and control-character-checked |
| E: Compromised server pushes code to agents | Updates come only from the agent listener over the pinned connection, checked against the SHA-256 in the authenticated report answer and test-started before they replace the binary. A server under attacker control can nevertheless run code as `varde-agent` on every self-updating agent (root where Docker access was granted); `VARDE_AGENT_AUTO_UPDATE=false` removes this at the cost of manual updates (ADR 0031) |
| I/E: Installation credentials leak | Entered once after the user compared the host key fingerprint; used for one SSH session through the network scope check and never stored, logged or rendered back; sudo reads the password on stdin; the enrollment token travels in an uploaded file in a `mktemp -d` directory, never on a command line, is valid fifteen minutes and deleted when the installation fails |
| I: The package lists of all hosts reach osv.dev | Only with the OSV switch, which the settings and the guide explain; queries carry package names, versions and releases, never host names or addresses (ADR 0032) |
| T: A compromised agent misreports image packages to hide findings elsewhere | Image records from an agent are stored only for images its own active containers use, never replace a successful record of another source (records carry their source), and are checked strictly (ADR 0033) |
| T: A host claims a pending restart or another kernel | The kernel release and restart notes are parsed strictly (fixed sections, release and package name patterns, at most 50 names) and only shown for that host; they change no finding |
| I: A Synology password, TrueNAS or Unraid API key or Home Assistant token disclosed | The setup asks for a user without admin rights (TrueNAS: a read-only role); the secret is stored encrypted like other service secrets, sent only to the pinned address, DSM sessions are closed after each read, and answers are bounded and validated before a version is kept |
| I: The SNMP community or v3 passphrases disclosed | Set only through the environment or files, never stored or shown; sent only to addresses inside the scope that answered the scan; only GET of three system objects; a read-only community or v3 user is documented |
| T: A device lies about itself in mDNS, UPnP or its version API | Names and versions are bounded and stripped of control characters; a UPnP description is fetched only from the answering address inside the scope; a forged version can at most hide or invent findings for that device |
| E: A UniFi API key used for more than reading | UniFi has no read-only keys: a key carries the rights of the admin with full rights who created it, so the setup says so and names it a secret to remove when unused; Varde only sends GET requests to the client list, the site ID from the answer is checked before it goes into a path, the certificate is pinned and the key is stored encrypted like other service secrets |
| S: A forged X-Forwarded-Proto makes Varde believe a connection is encrypted | The header counts only from `VARDE_TRUSTED_PROXIES`; from any other peer it is ignored and only used to name that peer in the hint |
| E: Agent user gains more than it needs | `varde-agent` has no login and no password; the systemd unit sets `NoNewPrivileges`, `ProtectSystem=strict` with only its own directory writable, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, an empty capability set; the `docker` group only when the user chose Docker access |
| E: Stolen agent key used after revocation | Certificate fingerprint compared with the stored pin on every request; revocation clears it and removes the host's workloads |
| R: Silent agent hides a host | Hosts missing three intervals become `stale`, raise a notice on the front page and in the daily digest |
| I: Agent listener exposes UI | Separate listener and port; mTLS required before any handler runs |
| T: A compromised agent changes what other hosts' containers are checked against | Image records are kept per source; a container uses Varde's own read of its image or the record of its own host's agent, never another agent's; a revoked agent's records are deleted (ADR 0033) |
| T: A compromised agent claims another device's address to hide its endpoint findings | Agents' addresses do not suppress endpoint results; an app an agent reads can show twice instead |
| E: A compromised agent turns a re-run of the push install into root | The agent's home belongs to root; the install refuses `bin` or `data` that are not plain directories and writes the binary where only root can before renaming it into place |
| D: A flood of agent reports starts analyses without end | Requests coalesce: one analysis runs, at most one waits |
| S: Unauthenticated clients obtain CA-signed certificates | The enrollment token is checked before the CA signs a certificate |

### Network discovery and integrations (boundary 8)

| Threat | Mitigation |
|---|---|
| S: Rogue host impersonates a Proxmox node or Docker host | Certificate fingerprint and SSH host key confirmed by the user and pinned; a change is refused; the SSH key type is pinned too |
| T: Scanned services return crafted titles or banners | Read with size and time limits, stored as text, HTML-escaped on output; never used for findings |
| I: Varde used to reach third parties (SSRF, scanning the internet) | Every connection checks the resolved address against the user's private ranges; public ranges cannot be allowed |
| I: Token secrets leak through a database copy | Sealed with AES-GCM under a key in a separate file, bound to the integration ID |
| E: Stolen Varde SSH key runs commands on hosts | The key line forces `docker system dial-stdio` with `restrict`; still grants the Docker API (root-equivalent), stated on the setup page |
| D: A scan floods a small network | Bounded concurrency and rate, IPv4 ranges up to /20, one scan at a time; scheduled scans are off by default and use the same limits |
| E: Stolen Proxmox key runs commands on the hypervisor | The key line for root on the node forces one fixed command (ADR 0024, ADR 0030): `pct list`/`qm list`, `pct config`/`qm config`, and per running guest `pct exec` or `qm guest exec` of fixed read-only commands (`cat` of fixed files, `rpm -qa`, `docker ps`, `docker image ls`), with `restrict`. `qm guest exec` runs them as root inside the VM through the agent; the forced command allows nothing else. It grants no shell; a stolen key yields the package lists of the node's containers |
| I: Registry queries reveal the running images | Off by default (ADR 0025); anonymous pull-scope tokens only; the registry already sees each pull |
| T: A registry or a crafted tag list misleads the version | Only the registry the image comes from is asked; tag-list links are followed on that registry only; a tag counts only when the digest the registry states for its manifest equals the running digest. The registry is trusted for this as far as it is trusted to serve the image: a malicious registry can claim any tag, as a malicious publisher can set any label |
| S/I: A registry's token realm points Varde at internal services (SSRF) | The realm must be on the registry's own host or domain, or a known token service (lscr.io → ghcr.io); IP literals other than the registry's own are refused (ADR 0025) |
| T: Registry tags or image references inject into the suggested update | Tags and references must follow the OCI grammar before they reach the copyable `image:` line (ADR 0029) |
| S: An image claims another project's source label | A derived entry needs the image name to match the repository name; its findings stay unverified until the user confirms the app; reviewed catalog entries always win |
| I: Service credentials leak or grant more than reading | Only services with a read-only credential are integrated (ADR 0024); secrets sealed with AES-GCM bound to the integration; https pinned by fingerprint; plain http flagged on the setup page because the credential then crosses the LAN unencrypted |
| T: A router or proxy reports false clients or routes | Clients are evidence (MAC, name, address), never a basis for findings; routes only annotate exposure and coverage; answers are size-capped and parsed strictly |
| T/S: A container forges the node's output (other containers, MACs of other machines, an early end) | Every line the node adds carries a nonce drawn on the node for the run, which no container can know; host names and MACs come from the node's `pct config`, never from inside the container; each container appears once (ADR 0024) |
| T/I: A container tricks the node command into reading host files | Files are read with `pct exec … cat` inside the container's namespaces and rights, never through `/proc/<pid>/root` from the host, where absolute symlinks resolve against the host |
| E: Stolen inventory key runs commands on hosts | A second key (ADR 0022) whose line forces one fixed read-only command (package lists, service list, `os-release`, `uname -n`) with `restrict`; it grants no shell, no forwarding and no Docker access |
| T: A compromised host sends crafted package or service lists | Output capped at 16 MiB and two minutes, parsed strictly (fixed sections, bounded fields); the package list is stored as data (names and versions, escaped in the UI); distribution packages are compared only with their distribution's records, never with upstream ranges. A host can lie about its own packages and hide or invent findings for itself, nothing more |
| S/T: A LAN device answers a version endpoint as an app it is not, or with a false version | Only catalog-defined endpoints, GET without credentials, no redirects, 64 KiB; a version counts only when the catalog's `expect` fields match. Residual risk: the response is not authenticated, so a device in the allowed ranges can fake an app and version for its own address, raising or hiding a finding for that address only. The evidence names the endpoint URL |

### Feed and direct sources (boundary 4)

| Threat | Mitigation |
|---|---|
| T: A2 serves forged advisories | Signature verification against embedded root keys (ADR 0005) |
| T: Rollback / freeze to hide a new advisory | Monotonic `sequence`, `expires_at`, staleness notice after 3 days |
| T: Mix-and-match of blobs | Content-addressed blobs referenced from the signed manifest |
| D: Decompression bombs, huge responses | Hash verified before decompression; hard size and uncompressed limits; absolute cap |
| T: Partial install after crash | Staged directory, atomic rename, previous bundle retained |
| I: Direct mode reveals which apps run (to GitHub, OSV) | Documented in UI and docs; OSV opt-in; feed mode avoids it |
| I: endoflife.date requests reveal product names | Opt-in (`EOL_DATA`); an answer for another product is refused (ADR 0029) |
| I: Chat channel secrets in URL paths (Discord webhook URL, Telegram bot token) | Secrets through environment variables or files only; redacted in every error the channels return (ADR 0029) |
| I: Distribution data queries reveal package names and releases to osv.dev | Under the same opt-in as OSV; only source packages of catalog apps are asked (ADR 0028) |
| T: A2 serves misleading distribution records | Records are matched only for the queried release and package; Debian, Ubuntu and Alpine keep only per-CVE records, AlmaLinux, Rocky Linux and openSUSE keep their notices and expand them per CVE without merging CVEs; pages are followed to the end (at most 20), an inconsistent answer is refused; an unparseable version makes the finding unverified, never affected |
| T/I: SSRF via catalog-defined URLs or probes | Probes disabled by default, only to the container's own internal address, no redirects, 64 KB cap; egress allowlist option; all HTTP through `internal/httpx` |

### Notifications (boundary 5)

| Threat | Mitigation |
|---|---|
| I: Secrets in logs or error messages | Secrets only via env/`*_FILE`, redacted in config dumps and errors |
| S: Spoofed or replayed webhook deliveries to the receiver | Optional HMAC-SHA256 over `<timestamp>.<body>` (`X-Varde-Timestamp`, `X-Varde-Signature`); receivers reject stale timestamps |
| T: Header or line injection via advisory text into mail and push messages | Control characters stripped and length bounded before rendering; RFC 2047 encoding for subjects |
| I: Tokens over plain HTTP to LAN notification servers | Allowed only for explicitly configured endpoints, with a startup warning; Gotify token sent as header, never in the URL; SMTP refuses servers without STARTTLS unless TLS mode is changed explicitly |
| R: Silent suppression of real issues | Suppressions require a reason, are scoped (workload or app) and optionally expire; creation and deletion are audited |
| I: Notification content leaks inventory to a third-party push service | Documented; users choose self-hosted ntfy/Gotify; content minimal |

### Catalog (boundary 6)

| Threat | Mitigation |
|---|---|
| T: A6 adds a matcher that hijacks another app's images or suppresses advisories | Schema validation, duplicate-matcher check in CI, no free regex on image names, maintainer review |
| D: ReDoS via version regexes | Go RE2 engine (linear time), length caps on patterns |
| D: YAML bombs | Size caps, aliases rejected or YAML compiled to JSON at build time |

### CI and release (boundary 7)

| Threat | Mitigation |
|---|---|
| T: A7 PR exfiltrates secrets or poisons caches | No `pull_request_target`; `contents: read`; `persist-credentials: false`; no secrets in PR workflows |
| T: Compromised third-party action | Actions pinned by full commit SHA, updated via Dependabot |
| T: Tampered image | Reproducible build flags, SBOM, cosign keyless signatures, SLSA provenance (release workflow) |
| T: Dev feed keys in release builds | Build tag plus CI check; development roots refused by default |

## Residual risks

- A container controls its own metadata and can misrepresent its identity or version. Varde reports
  what the container claims; precision rules limit, but cannot remove, this.
- Exposure detection is heuristic; router port forwards are invisible to Varde.
- Attack paths are a model built from that exposure and from heuristic port and library maps
  (ADR 0034). A finding marked as noise can still matter where Varde's view is incomplete (a port
  forward to a host service, an app using a library in an unusual way); the reason is always
  shown, and noise stays listed and in the weekly digest.
- Direct mode leaks the set of apps in use to upstream APIs from the user's IP.
- A compromised feed signing pipeline can publish a validly signed but incomplete feed. Further
  feed limits are listed in `docs/feed-trust.md`.
- On a plain-HTTP LAN (`VARDE_COOKIE_SECURE=never`) session cookies and passwords cross the network
  unencrypted; the UI warns permanently. TLS termination is the user's responsibility.
- The internal CA key (`/data/ca/ca.key`) lets whoever holds it issue agent certificates; they are
  still rejected without a matching pin, but backups of `/data` must be protected.
- A revoked agent keeps retrying with backoff (at most once a minute) until it is stopped.
- Self-updating agents trust the server: whoever controls it can run code on their hosts
  (ADR 0031). Agents without Docker access run as an unprivileged user, so this is root only where
  Docker access was granted.
- On plain HTTP an attacker controlling a sibling subdomain can perform login CSRF (signing the
  victim in to the attacker's own account). Accepted; HTTPS removes it (`docs/security-review.md`).
- `pct exec` runs the container's own `cat` as the container's root through lxc-attach. On a node
  with an unpatched LXC, historic lxc-attach escapes (the CVE-2016-8649 class) matter for
  privileged containers; keep the node updated, prefer unprivileged containers.
- Whoever controls the Varde server can use its SSH key against every connected Docker host, which
  equals root there. Docker offers no read-only API; a socket proxy on the host behind the SSH
  forced command would reduce this and is a possible later option.
- The socket proxy allows every GET under `/containers`, including the archive and export
  endpoints: whoever controls the Varde server can read any file of any container, secrets in
  environment files included. Varde itself requests only the fixed package files (ADR 0026); the
  proxy cannot restrict paths.
- Discovery cannot see hosts without any open probed port behind Docker Desktop, where refused
  connections arrive as timeouts.
- During a login flood from many addresses, legitimate logins may get "busy" (503) for the
  duration: hashing is serialised to bound memory, and waiting is capped at 3 s.
