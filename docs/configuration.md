# Configuration

Precedence: built-in defaults < values saved in the Settings page < environment. A setting given by
environment variable is shown locked in the UI; remove the variable to manage it there. The UI
manages exposure domains, the networks Varde may contact, digest schedule, the opt-in sources (OSV,
NVD) and the P1/P2 policy thresholds; everything else, including notification channels and their secrets, is environment
only. Every secret can be given directly or via
`NAME_FILE` pointing to a file; setting both is an error. Invalid configuration stops the process
with all problems listed at once.

`internal/config/config_test.go` fails if a variable read in `internal/config/config.go` is missing
from the table below.

| Variable | Default | Description |
|---|---|---|
| `VARDE_LISTEN_ADDR` | `:8080` | UI/API listener (`host:port`). |
| `VARDE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |
| `VARDE_LOG_FORMAT` | `json` | `json` or `text`. |
| `VARDE_DATA_DIR` | `/data` | Absolute path holding the database. The only writable path. |
| `VARDE_DOCKER_HOST` | `tcp://socket-proxy:2375` | Engine API endpoint: `tcp://`, `http://`, `https://`, `unix://` (only with `VARDE_ALLOW_DIRECT_SOCKET`), or `off` to disable the local Docker collector. |
| `VARDE_ALLOW_DIRECT_SOCKET` | `false` | Accept a `unix://` Docker host or a socket mounted at `/var/run/docker.sock`. Gives a compromised Varde root on the host. |
| `VARDE_AGENT_LISTEN_ADDR` | `:8443` | mTLS listener for agents (`host:port`), or `off`. Publish it only when agents are used; it serves nothing without a client certificate except enrollment. |
| `VARDE_AGENT_BINARY_DIR` | `/usr/lib/varde/agent` | Agent binaries (`varde-linux-amd64`, `varde-linux-arm64`) the server installs on hosts and offers agents as updates. The image contains them; for a binary installation, put the release binaries there. A missing directory switches both off. |
| `VARDE_RESYNC_INTERVAL` | `6h` | Full inventory resync period (Go duration, at least `1m`). Changes are picked up from Docker events in between. |
| `VARDE_CATALOG_DIR` | `/catalog.d` | Optional directory of local catalog entries (`*.yaml`, same schema as `docs/catalog.md`). Entries with a built-in ID replace it; all are marked `local`. A missing directory is ignored; an invalid entry stops the server. |
| `VARDE_MODE` | `direct` | Where advisories come from: `direct` (Varde queries the upstream sources itself), `feed` (signed central feed only) or `hybrid` (feed, plus direct sources for local catalog entries and apps the feed does not cover). See [feed-trust.md](feed-trust.md). Setting it fixes the mode and locks the uplink switch under Settings; leave it unset to let that switch decide (see [The uplink switch](#the-uplink-switch)). |
| `VARDE_FEED_URLS` | unset | Feed mirrors in order, comma-separated; required in `feed` and `hybrid` mode, and what the uplink switch fetches from when `VARDE_MODE` is unset. `https://` URLs, or `file:///path` for a local directory or a `.tar` file (air-gapped import, same verification). Mirrors are untrusted: integrity comes from the signatures. |
| `VARDE_FEED_ROOT_FILE` | unset | Initial trust root (`root.json`) of the feed; needed on first start in `feed`/`hybrid` mode. Later roots are fetched and verified against it. |
| `VARDE_FEED_ALLOW_DEVELOPMENT_ROOT` | `false` | Accept a trust root marked `development` (feeds built with `cmd/feedbuilder`). Only for tests; without it such roots are refused, also when a rotation tries to switch to one. |
| `VARDE_FEED_STALE_AFTER` | `72h` | A system notice appears when no feed manifest verified for this long (at least `1h`). |
| `VARDE_ADVISORY_REFRESH` | `6h` | Period of scheduled advisory refreshes (at least `1h`, jittered by ±30 min). New apps trigger an extra refresh. KEV, EPSS and NVD refresh daily. |
| `VARDE_GITHUB_TOKEN` / `VARDE_GITHUB_TOKEN_FILE` | unset | Optional GitHub token (no scopes needed) for 5000 instead of 60 API requests per hour. |
| `VARDE_PACKAGE_URLS` | `https://raw.githubusercontent.com/bifrost0x/varde/data/feed` | Mirrors of the data package in order, comma-separated: `https://` URLs, or `file:///path` for a directory or a `.tar` file in a mounted volume (installations without internet access; same verification). Set it to an empty value to switch the data package off. The package is only used once a trust root exists (built in, or `VARDE_FEED_ROOT_FILE`) and `VARDE_MODE` is unset. See [The data package](#the-data-package). |
| `VARDE_DIRECT_QUERIES` | `false` | With the data package in use: also ask api.github.com about apps the package does not cover, which shows GitHub which of those you run. osv.dev, NVD and endoflife.date have switches of their own. Without a data package Varde always asks GitHub. |
| `VARDE_DIRECT_OSV` | `false` | Query osv.dev for catalog `osv_packages`, and check distribution packages (Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, openSUSE Leap) against their distribution's security data (ADR 0028). Reveals the package names of the apps you run, and the releases of those distribution packages, to osv.dev. |
| `VARDE_DIRECT_NVD` | `false` | Query the NVD CVE API by catalog CPEs (ADR 0017). Reveals which products you run to NIST. |
| `VARDE_NVD_API_KEY` / `VARDE_NVD_API_KEY_FILE` | unset | Optional NVD API key for higher rate limits. |
| `VARDE_SNMP_COMMUNITY` / `_FILE` | unset | SNMP v2c community; network scans then read the system description and name of devices that answered (switches, UPS, printers, NAS). Use a read-only community. |
| `VARDE_SNMP_USER` | unset | SNMP v3 user instead of a community, with SHA-256 authentication. |
| `VARDE_SNMP_AUTH` / `_FILE` | unset | SNMP v3 authentication passphrase; required with `VARDE_SNMP_USER`. |
| `VARDE_SNMP_PRIVACY` / `_FILE` | unset | SNMP v3 privacy passphrase (AES); without it v3 runs authenticated but unencrypted. |
| `VARDE_EGRESS_ALLOWLIST` | unset | Comma-separated host names; when set, every outbound request to another host is refused. Direct mode needs `api.github.com`, `www.cisa.gov`, `api.first.org`, plus `api.osv.dev` / `services.nvd.nist.gov` / `endoflife.date` when enabled, and `discord.com` / `api.telegram.org` for those channels. Add the hosts of your ntfy, Gotify, webhook and SMTP endpoints, and with registry versions on the registries your images come from (`registry-1.docker.io`, `auth.docker.io`, `ghcr.io`, `lscr.io`, `quay.io`, ...). |
| `VARDE_CA_BUNDLE_FILE` | unset | PEM file with additional CA certificates (TLS-inspecting proxies, private mirrors). Used by every outbound client: advisory sources, notification channels and registries. |
| `VARDE_HOST_ADDRESS` | unset | Comma-separated IP addresses of the machine Varde runs on, in your network. In a container Varde only sees its bridge address; with this set, "this host" and the device the network scan finds for it are one machine, and agent installs default to this address. |
| `VARDE_PUBLIC_DOMAINS` | unset | Comma-separated domain suffixes reachable from the internet. A Traefik router serving such a host marks the container `public`. |
| `VARDE_INTERNAL_DOMAINS` | unset | Domain suffixes only used inside the LAN (e.g. `home.arpa`, `lan`); matching routers mark the container `lan`. |
| `VARDE_BASE_URL` | unset | External address of the Varde UI, used for links in notifications. |
| `VARDE_NTFY_URL` | unset | ntfy topic URL, e.g. `https://ntfy.example.com/varde`. `http://` is accepted for LAN servers; the token then travels unencrypted. |
| `VARDE_NTFY_TOKEN` / `VARDE_NTFY_TOKEN_FILE` | unset | ntfy access token (sent as `Authorization: Bearer`). |
| `VARDE_GOTIFY_URL` | unset | Gotify server URL. |
| `VARDE_GOTIFY_TOKEN` / `VARDE_GOTIFY_TOKEN_FILE` | unset | Gotify application token (sent as `X-Gotify-Key`, never in the URL). Required with `VARDE_GOTIFY_URL`. |
| `VARDE_DISCORD_WEBHOOK_URL` / `VARDE_DISCORD_WEBHOOK_URL_FILE` | unset | Discord webhook URL (Server settings › Integrations › Webhooks). It contains the webhook token, so it is a secret and redacted in errors. Messages never mention users or roles. |
| `VARDE_TELEGRAM_TOKEN` / `VARDE_TELEGRAM_TOKEN_FILE` | unset | Telegram bot token from BotFather; redacted in errors. |
| `VARDE_TELEGRAM_CHAT_ID` | unset | Chat the bot writes to: a numeric chat ID or `@channelname`. Required with `VARDE_TELEGRAM_TOKEN`. Messages are plain text. |
| `VARDE_WEBHOOK_URL` | unset | Receives `POST` with a JSON message (`version`, `kind`, `priority`, `title`, `text`, `items`). |
| `VARDE_WEBHOOK_SECRET` / `VARDE_WEBHOOK_SECRET_FILE` | unset | When set, requests carry `X-Varde-Timestamp` and `X-Varde-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`. Reject stale timestamps on the receiver. |
| `VARDE_SMTP_HOST` | unset | SMTP server; enables mail. |
| `VARDE_SMTP_PORT` | `587` | SMTP port. |
| `VARDE_SMTP_TLS` | `starttls` | `starttls` (refuses servers without STARTTLS), `tls` (implicit TLS, usually port 465) or `none` (only for a local relay; credentials are refused over plain connections to remote hosts). |
| `VARDE_SMTP_USERNAME` | unset | SMTP user. |
| `VARDE_SMTP_PASSWORD` / `VARDE_SMTP_PASSWORD_FILE` | unset | SMTP password. |
| `VARDE_SMTP_FROM` | unset | Sender address (required with `VARDE_SMTP_HOST`). |
| `VARDE_SMTP_TO` | unset | Comma-separated recipients (required with `VARDE_SMTP_HOST`). |
| `VARDE_DIGEST_HOUR` | `8` | Local hour (0-23, container `TZ`) of the daily P2 digest and the weekly P3 digest. |
| `VARDE_DIGEST_WEEKDAY` | `monday` | Day of the weekly digest. |
| `VARDE_COOKIE_SECURE` | `auto` | Session cookie `Secure` attribute: `auto` (when the request arrived over TLS, directly or via a trusted proxy), `always`, or `never` (plain-HTTP LAN; the UI shows a warning). |
| `VARDE_BEHIND_TLS_PROXY` | `false` | Varde runs behind a TLS-terminating reverse proxy: cookies are always `Secure` and HSTS is sent. |
| `VARDE_TRUSTED_PROXIES` | unset | Comma-separated IPs or CIDRs allowed to set `X-Forwarded-For` / `X-Forwarded-Proto`. Default: none, headers are ignored. When a request claims HTTPS from a peer that is not listed, the UI names that peer and the line to set. |
| `VARDE_API_TOKEN` / `VARDE_API_TOKEN_FILE` | unset | Optional static bearer token (at least 32 characters) with write scope, for automation that must work before any user exists. Tokens created in the UI are preferred. |

## First login

On first start, while no account exists, Varde logs a one-time setup token (valid 24 hours). The
setup page shows these commands with the name of Varde's container; copy the value after
`setup_token=`:

```sh
docker logs varde 2>&1 | grep setup_token                     # Linux, macOS
docker logs varde 2>&1 | findstr setup_token                  # Windows cmd
docker logs varde 2>&1 | Select-String setup_token            # Windows PowerShell
docker compose logs varde | grep setup_token                  # Docker Compose
journalctl -u varde | grep setup_token                        # without Docker
```

Open the UI, enter the token and create the first account. A restart before setup prints a new
token. Further accounts and API tokens are created under Settings; API tokens are shown once.

Locked out? Set a new random password where the server runs:

```sh
docker exec varde /varde reset-password <user>
```

## Network discovery and integrations

Varde finds hosts and reads their inventory without agents (ADR 0020). Everything is set up under
**Connections**:

1. **Allow networks.** Enter the private ranges Varde may contact, for example
   `192.168.1.0/24, 10.0.10.0/24`. Varde never connects to an address outside them, for scans or
   integrations. IPv4 ranges up to a /20 can be scanned. The same field is under Settings.
2. **Scan.** Varde connects to common homelab ports (SSH, HTTP/HTTPS, Proxmox, Docker, Portainer,
   Home Assistant, SMB, DNS), reads what the services announce and lists the devices with what Varde
   reads them as. A port that answers on almost every address (a router redirecting all DNS, for
   example) is ignored and named on the page.
3. **Connect platforms.**
   - **Proxmox VE**: confirm the node's certificate fingerprint, then create a read-only token in
     the node shell:
     `pveum user add varde@pve`, `pveum acl modify / --users varde@pve --roles PVEAuditor`,
     `pveum user token add varde@pve varde --privsep 0`. Varde reads nodes, VMs and containers with
     their addresses. VM addresses come from the QEMU guest agent; on Proxmox 8 they also need
     `VM.Monitor`.
   - **Docker host over SSH**: confirm the host key fingerprint (the page names the
     `ssh-keygen -lf` command to compare with) and add the key line the page shows to
     `~/.ssh/authorized_keys` of a user in the `docker` group. The line only allows
     `docker system dial-stdio`. Docker access equals root on that host; keep the Varde server
     private.
   - **Every guest of a Proxmox node**: on the Proxmox device or integration choose "Read all
     guests", confirm the node's host key and run the commands of step 3 on the node. The key line
     forces one fixed command that reads, for each running LXC container (`pct exec`) and each VM
     whose QEMU guest agent answers (`qm guest exec`), the package databases and the Docker
     containers inside (ADR 0024, ADR 0030). For VMs, install `qemu-guest-agent` in the VM and
     enable "QEMU Guest Agent" in its options. Connect each node once. Key lines of an earlier
     version of the command must be replaced (run step 3 again).
   - **Traefik, Nginx Proxy Manager, Fritz!Box, OPNsense, UniFi**: under "Connected platforms"
     choose "Add …", or "Connect …" on a device the scan recognised. The setup names the read-only
     credential to create (Traefik: none or the dashboard's basic auth; Nginx Proxy Manager: a user
     with Proxy Hosts: View; Fritz!Box: a user without rights; OPNsense: an API key of a user with
     only Diagnostics: ARP Table and ISC DHCPv4: Leases; UniFi Network 9.0 or later: an API key from the
     Network app's integration settings; UniFi has no read-only keys and lets only an admin with
     full rights create one, so the key carries those rights and Varde only sends read requests). Proxies report which host names point where; routers report the devices with MAC and
     name. https certificates are pinned; http works but sends the credential unencrypted.
   - **Synology DSM, QNAP, TrueNAS, Unraid, Home Assistant OS** (ADR 0036): the same way. Each
     integration reads the system's own version and records it as a system with a firmware
     package, which the catalog checks against advisories. Synology: a DSM user without admin
     rights and without two-factor sign-in (Varde signs in, reads SYNO.DSM.Info and signs out);
     QNAP: no credential (the sign-in page reports the firmware); TrueNAS: an API key of a user
     with a read-only role; Unraid 7.2 or later (or the Connect plugin): an API key with read access
     to system information; Home Assistant OS or Supervised: a long-lived token of a user without
     admin rights. Advisories for these products come mostly from NVD (`VARDE_NVD_API_KEY`) or the
     central feed; without either, the version is still shown with its end-of-life state.
   - **Packages over SSH**, for apps installed natively in VMs and LXC containers: confirm the host
     key as above and add the second key line the page shows to `~/.ssh/authorized_keys` of any
     user. The line forces one fixed, read-only command that lists the dpkg, rpm or apk packages,
     the systemd services, the running kernel and Debian's and Ubuntu's restart notes; it grants
     no shell. Varde keeps the full package list, reads it every hour and, with the osv.dev source
     on, checks every package against its distribution's security data (ADR 0032). The agent runs
     the same command. Key lines of an earlier version keep working but send no kernel and restart
     information; replace them to get it.
4. **Versions from the apps.** After each scan Varde asks web services for the documented version
   endpoint of apps in the catalog (for example Jellyfin's `/System/Info/Public`). Only an answer
   that proves it comes from the app counts. Proxmox VE's version comes from its API.
5. **Scan automatically.** Off by default; every 6 hours, daily or weekly under Connections or
   under Settings. Scheduled scans use the same limits as a scan on request.

The scan probes SSH, HTTP/HTTPS, Proxmox VE and Backup Server, Docker, Portainer, Home Assistant,
Jellyfin, Navidrome, Nginx Proxy Manager, SMB and DNS ports.

Each integration can be switched off or removed; removing it deletes the hosts it reported. An
integration that has not read successfully for three of its intervals (Proxmox every 10 minutes,
Docker over SSH every 15, packages every hour) is shown as not reading, its hosts count as not reporting, and a notice goes
into the daily digest. The last scan result is kept across restarts. Token
secrets are stored encrypted with a key in `<data>/keys`; Varde's SSH keys are `<data>/ssh/id_ed25519`
(Docker), `<data>/ssh/id_ed25519_inventory` (packages) and `<data>/ssh/id_ed25519_proxmox`
(containers of Proxmox nodes). The front page and Connections list the next steps, ranked by
what they show.
Back up the whole data directory together.

## Versions of floating tags

Containers started from `latest`, `stable` or similar tags carry no version Varde can read when the
image has no version label. Under **Settings › Versions of floating tags** Varde may ask the image's
registry which release tag points to the running digest (ADR 0025): anonymous, read-only, cached
per digest. It is off by default. With `VARDE_EGRESS_ALLOWLIST`, add the registries you pull from
(`registry-1.docker.io` and `auth.docker.io` for Docker Hub, `ghcr.io`, `lscr.io`, …).

Under the same heading, **Read the package lists of images from their containers** (on by default)
lets Varde read `/etc/os-release` (or `/usr/lib/os-release`), `/var/lib/dpkg/status`,
`/lib/apk/db/installed` and the rpm database (`/var/lib/rpm/rpmdb.sqlite` or
`/usr/lib/sysimage/rpm/rpmdb.sqlite`) from one container per image, once a week (ADR 0026). An app installed from its project's own package gives
its version this way, and a tag that disagrees with the installed package is flagged as a conflict.
Varde also reads the app's own `package.json` in the image's working directory or its parent, when
it carries the app's name; on development tags such as `main` that version is only reported.
Agents read the images of their own containers the same way while this setting is on (ADR 0033).
With the osv.dev source on, the packages of every image are checked against their distribution's
security data; a finding there is fixed by a newer image, not by a package update inside the
container. The same setting reads the app's `package-lock.json` next to its `package.json`, and
streams the program the image runs (its entrypoint or command, at most four candidates, 512 MB
each) to take the Go build information from it; nothing else of the program is kept. Their
dependencies are checked against osv.dev's Go and npm data.

The analysis builds attack paths from what Varde knows (ADR 0034) and needs no setting. It
improves with the data you give it: public domains and proxy integrations for paths from the
internet, the network scan and agents or SSH inventories (which report the ports a host listens
on) for paths from the LAN. A finding is called background noise only when Varde knows why no
path uses it.

The inventory flags two kinds of container drift (ADR 0027). **Newer image pulled**: the container's
tag points to a newer local image than the one it runs, so recreate the container
(`docker compose up -d`). **Changed inside**: package databases or the app's manifest were changed
inside the container, so Varde does not use their evidence from the image. The second check runs
only while package reading is on.
It needs no further access: the socket proxy already allows the archive endpoint. Turn it off if you
do not want Varde to read files of containers at all.

With registry versions on, Varde also reads the tag list of each repository whose containers have
affected findings (once a day), so the finding page can name the release tag that fixes them, in
the form of the running tag, with the Compose line to change and the commands (ADR 0029).

**Read release lines from endoflife.date** (Settings › Versions, off by default) marks versions on
release lines that no longer get fixes, for catalog apps endoflife.date tracks. It reveals those
product names to endoflife.date, once a day.

Apps that are not in the catalog are recognised automatically when the image's source label names a
GitHub repository whose name matches the image. They show as "recognised automatically"; their
findings alert once you confirm the app with the container label `varde.app=<id>`.

## Agents

The agent reports the full inventory of the host it runs on to the server over mTLS (ADR 0011,
ADR 0031): every installed package (the same inventory the SSH inventory reads, ADR 0030) and,
with Docker access, every container. It needs no inbound port, so it also covers hosts in another
VLAN or behind a VPN.

**Install it from Varde.** After a scan, the front page and each found Linux host offer "Install the
agent"; one run covers up to 20 hosts with the same user and credentials, each with its own host key
to confirm. Under Connections › Agents choose "Install the agent on a host" (or "Install the
agent" on a system's page): enter the address and a user (root, or one who may use sudo), compare
the host key fingerprint, and enter the password or paste a private key once. Varde signs in for
this one session and stores neither. It uploads the agent binary for the host's platform
(linux/amd64 or linux/arm64), a configuration with a one-time token and an install script, and runs
the script as root. The script creates the system user `varde-agent` without a login, installs the
agent to `/var/lib/varde-agent`, its configuration to `/etc/varde-agent.env` and a hardened systemd
service (or an OpenRC service on Alpine), and starts it. With "Read the Docker containers" the user
joins the `docker` group, which is equivalent to root on that host; without it the agent runs
without privileges and reports the packages only. Running the installation again updates it.

**Updates.** The server offers the agent binary of its own version with every report answer, by
its SHA-256. An installed agent downloads it over the pinned connection, checks the checksum and
that it starts, replaces itself and restarts. Agents in the container image update with the image.
`VARDE_AGENT_AUTO_UPDATE=false` switches this off. Update the server before agents you run
yourself: an older server refuses reports of a newer agent.

**Remove it** from a host, as root (signed in as another user, `sudo` in front or `su -c`). With
systemd:

```sh
sudo sh -c 'systemctl disable --now varde-agent; rm -f /etc/systemd/system/varde-agent.service /etc/varde-agent.env; systemctl daemon-reload; rm -rf /var/lib/varde-agent; userdel varde-agent'
```

With OpenRC (Alpine):

```sh
sudo sh -c 'rc-service varde-agent stop; rc-update del varde-agent; rm -f /etc/init.d/varde-agent /etc/varde-agent.env; rm -rf /var/lib/varde-agent; deluser varde-agent'
```

Then revoke it under Connections › Agents.

**Run it yourself**, for example with `deploy/compose.agent.yaml`: create an enrollment token on the
Connections › Agents (valid one hour, single use, shown once); it contains the fingerprint of the server's
internal CA, so the agent verifies the server on first contact. After enrollment the agent authenticates with its own client
certificate (90 days, renewed automatically 30 days before expiry). Revoking an agent under
Connections › Agents rejects its next request.

| Variable | Default | Description |
|---|---|---|
| `VARDE_SERVER_URL` | required | Agent listener of the server, e.g. `https://varde.lan:8443`. |
| `VARDE_ENROLL_TOKEN` / `VARDE_ENROLL_TOKEN_FILE` | unset | One-time enrollment token; needed only until the first successful start. |
| `VARDE_AGENT_NAME` | Docker host name, or the system's host name without Docker | Name shown under Systems. |
| `VARDE_AGENT_AUTO_UPDATE` | `true` | Replace the agent binary with the one the server offers, when the agent may write it. |
| `VARDE_AGENT_INTERVAL` | `15m` | Full check and heartbeat interval (`1m` to `24h`). Docker events trigger reports in between. A host that misses three intervals is shown as not reporting. |
| `VARDE_DATA_DIR`, `VARDE_DOCKER_HOST`, `VARDE_ALLOW_DIRECT_SOCKET`, `VARDE_LOG_LEVEL`, `VARDE_LOG_FORMAT` | as for the server | The agent keeps its key, certificate and state in `VARDE_DATA_DIR` (a small volume). `VARDE_DOCKER_HOST=off` reports the host inventory only. |

`deploy/compose.agent.yaml` is a complete example. Health check: `varde healthcheck agent`
succeeds while the last report is younger than three intervals.

## Docker access through the socket proxy

Varde talks to Docker only through a read-only socket proxy (ADR 0006). Verified configuration
for `tecnativa/docker-socket-proxy` v0.5.0:

```yaml
socket-proxy:
  image: tecnativa/docker-socket-proxy:v0.5.0
  environment:
    CONTAINERS: 1
    IMAGES: 1
    INFO: 1
    EVENTS: 1
    VERSION: 1
    PING: 1
    POST: 0
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
  networks: [varde-internal]
  read_only: true
  tmpfs: [/run, /tmp]          # the proxy renders its haproxy config into /tmp
  security_opt: [no-new-privileges:true]
```

With this configuration the proxy answers `GET /containers/json` and refuses `POST`, `DELETE`,
`/secrets` and `/volumes` with 403 (checked against Docker Engine 29). Put the proxy on a network
with `internal: true` so it has no egress; Varde joins that network and the default network for
outbound HTTPS.

Varde refuses to start when a Docker socket is mounted at `/var/run/docker.sock`, even if it is
not used, unless `VARDE_ALLOW_DIRECT_SOCKET=true`.

## Recognising apps the catalog does not know

The catalog names a few dozen apps. For every other container Varde looks the image up in a table
that ships with it, the first-party index (`index/images.tsv`, about 150 KB), and reads the
advisories of the project's GitHub repository.

- **No download.** The table is part of the binary. An installation fetches nothing to recognise
  apps, neither at the first start nor later.
- **What a row rests on.** What the project or the registry states itself: the project's README
  or Compose file names the image, the image's Docker Hub page links the project, or the image is
  in the project's namespace on GitHub's registry. Two such statements confirm a row and its
  findings alert. One alone is a report: the findings are shown as unverified until you confirm
  the app with the label `varde.app=<id>` the inventory shows.
- **Where it comes from.** The project builds the table centrally, once for everyone, and reviews
  it like any other change (`index/SOURCES.md`). It is rebuilt weekly.
- **What it does not know.** A repackaged app (`binhex/arch-plex`) is recognised as its packaging
  project; the advisories of the app inside are then not read. Apps that came through no public
  project stay "not in catalog".
- **How it is updated.** With Varde itself: a new release carries the table of its build date.
- **What always wins.** A reviewed catalog entry and the image's own source label.

The inventory marks such apps "recognised automatically" and says what the recognition rests on.

## The data package

The project builds one signed data package a day: the advisories of every app the catalog and the
first-party index know, the KEV list, EPSS scores for those advisories, the catalog and the index
table itself. An installation that reads it asks nobody else about its apps: one mirror, two small
requests a day, and the changed parts of the package when there are any. The mirror sees an IP
address and that it fetches the Varde package, not which apps run there.

**The package is the default.** Varde carries the project's trust root
(`internal/feed/roots/production.json`, made in the key ceremony of
[data-package.md](data-package.md)), so with `VARDE_MODE` unset it reads the package and asks no
public source about your apps. A build without that file has no trust root: Settings › Data
package then says "not available" and Varde asks the public sources itself.

- **Where it comes from.** `VARDE_PACKAGE_URLS`, by default the branch `data` of the project's
  repository on `raw.githubusercontent.com`. The mirror is not trusted: every package is verified
  against the trust root (signatures, validity period, rollback and freeze protection, see
  [feed-trust.md](feed-trust.md)). With `VARDE_EGRESS_ALLOWLIST` set, add the mirror's host.
- **How often.** About once a day: at the first advisory refresh that comes 24 hours after the last successful check. A check that failed is repeated with the next advisory
  refresh (`VARDE_ADVISORY_REFRESH`).
- **Update now.** Settings › Data package › "Update now" checks the mirror at once and installs
  the newest package, whatever Varde version is running. If the package is in a newer format than
  this version reads, the section says so; the package in use stays until Varde is updated.
- **When it fails.** The last verified package stays in use, the section names the reason, and
  after `VARDE_FEED_STALE_AFTER` a notice appears on the front page. Varde never starts asking the
  public sources by itself because the package could not be fetched.
- **Without internet access.** Put the package (a directory or a `.tar` of it) into a mounted
  volume, set `VARDE_PACKAGE_URLS=file:///path`, and press "Update now" after replacing the file.
  The verification is the same.
- **Apps the package does not cover.** Your own catalog entries (`VARDE_CATALOG_DIR`) and images
  recognised only by their source label are not in the package. They are listed under Systems ›
  Gaps as "no advisory source". To have them checked, switch on "Also ask public sources directly"
  in the same section (`VARDE_DIRECT_QUERIES`): Varde then asks api.github.com about those apps,
  and only those, which shows GitHub which of them you run.
- **Release notes.** Many projects name part of their security fixes only in their release
  notes. The package carries those of every app whose advisories are not complete (ADR 0044).
  They never make a version affected: a version below such a release shows a finding to check
  yourself, with the release that fixes it and the lines of the notes, and nothing is sent.
- **What is not in it.** Distribution package data (Debian, Ubuntu, Alpine and the others),
  osv.dev package data, NVD and endoflife.date. Their switches under Settings › Optional advisory
  sources work the same with and without the package, and what they find counts beside the
  package's advisories. EPSS scores for the CVEs they bring are fetched from FIRST while one of
  them, or direct queries, is on; the package carries scores for its own CVEs.
- **Switching it off.** `VARDE_PACKAGE_URLS=` (empty) or `VARDE_MODE=direct`. What the package
  installed is removed at the next start.
- **Recognition.** The index table in the package is asked before the one built into the binary,
  so new images are recognised without a Varde update. An installation still downloads no lists
  and no pages to recognise apps: the table is part of the one package.

Trying it against a local development package (never in production):

```sh
go run -tags feeddev ./cmd/feedbuilder -keys ./dev-keys -out ./feed -channel package -index index/images.tsv
VARDE_PACKAGE_URLS=file:///abs/path/feed VARDE_FEED_ROOT_FILE=/abs/path/dev-keys/root.json \
  VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true varde server
```

## The uplink switch

Varde is complete without any service of the project: it asks the public sources itself. The
uplink is an optional paid data feed from the project's servers (ADR 0037); the same container
uses it after a license is entered under Settings › Uplink. Nothing is restarted and the Compose
file does not change.

- **Switching on.** Paste the license and choose "Switch on". Varde checks the license on the
  machine (signature against the feed's trust root, validity period), then fetches the feed once
  with it. Only when both work does the mode change; otherwise the reason is shown and Varde stays
  as it was.
- **While it is on.** Advisories, KEV and EPSS come from the feed, which takes the place of the
  data package. GitHub is asked about apps the feed does not cover only if "Also ask public
  sources directly" is on (Settings › Data package); an installation with the uplink but without
  the data package always asks. If the mirrors cannot be reached,
  the last verified feed stays in use and the stale notice appears. The license is sent to the feed
  mirrors only, as an `Authorization` header over TLS, and only while the uplink is on.
- **Switching off, expiry.** "Switch off" returns to the data package, which is fetched at once;
  until it is installed the uplink's last verified data stays in use. In an installation without
  a data package it returns to the public sources, the feed's
  advisories are removed and the built-in catalog is used again. The same happens by itself when
  the license expires. The license stays stored (encrypted with the key in `<data>/keys`) until
  "Remove license".
- **When it ends by itself.** An expired or unusable license raises a system notice on the front page
  and in the notifications, so the return to the public sources does not go unnoticed.
- **Advisories while it is on.** An app the feed covers is judged by the feed alone. What the
  public sources stored for it earlier stays in the database, unused, and counts again after
  switching off.
- **Slow servers.** A switch-on that gets no answer within 20 seconds changes nothing and says so.
- **Not available in this build.** The uplink service does not exist yet, so releases carry no
  trust root for it and the section says so. Nothing else is affected.
- **Environment.** `VARDE_MODE` fixes the mode and locks the section. With `VARDE_MODE` unset,
  `VARDE_FEED_URLS` and `VARDE_FEED_ROOT_FILE` supply the mirrors and the trust root the switch
  uses.

Trying it against a local development feed (never in production: development roots are refused
unless explicitly allowed):

```sh
go run -tags feeddev ./cmd/feedbuilder -keys ./dev-keys -out ./feed -channel uplink -license ./dev-keys/license.json
VARDE_FEED_URLS=file:///abs/path/feed VARDE_FEED_ROOT_FILE=/abs/path/dev-keys/root.json \
  VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true varde server
# Settings › Uplink: paste the content of dev-keys/license.json, "Switch on".
```

## Privacy in direct mode

With the data package in use, none of this applies unless you switch direct queries on, and then
only for the apps the package does not cover.

In direct mode Varde queries upstream sources itself, from your IP address. GitHub learns which
repositories' advisories you request, i.e. which apps you run. CISA (KEV) and FIRST (EPSS) see only
requests for the public catalog and for CVE IDs. OSV and NVD would learn package and product names
and are therefore off unless enabled. Feed mode avoids all of this: every client downloads
the same signed feed.

All outbound requests use HTTPS only, a fixed User-Agent (`varde/<version> (+repository URL)`)
without installation data, honour `HTTPS_PROXY`/`NO_PROXY`, follow redirects only to the same host
and have size limits per request type.

## Health endpoints

- `GET /healthz`: liveness, no authentication, no details. Used by `varde healthcheck`.
- `GET /readyz`: `200` when the database answers and the last inventory sync succeeded, `503`
  otherwise. The reason is logged at debug level, never returned.

## Backup, restore and upgrades

`/data` holds the database, the agent CA (`ca/`), the keys that encrypt integration secrets
(`keys/`) and Varde's SSH identity (`ssh/`). Losing the CA means every agent has to enroll again;
losing the keys makes stored integration secrets unreadable.

- **Backup while running:** `docker exec varde /varde backup /data/varde-backup.tar`, then
  `docker cp varde:/data/varde-backup.tar .` and delete the copy in the volume. The database is
  copied consistently (SQLite `VACUUM INTO`); a plain copy of a running database can be broken.
  The archive holds the CA and keys: store it like the data directory.
- **Restore:** stop Varde, then unpack into an empty volume, for example
  `docker run --rm -v varde-data-new:/data -v "$PWD/varde-backup.tar:/backup.tar:ro" ghcr.io/bifrost0x/varde:<version> restore /backup.tar`,
  and start Varde with that volume. Restore refuses a data directory that already holds a database.
- **Upgrade:** take a backup, change `VARDE_VERSION` (or, on `latest`, `docker compose pull`),
  `docker compose up -d`. Migrations run at
  start and only add to the schema. A newer database is refused by an older Varde, so a downgrade
  is a restore of the backup taken before the upgrade.
