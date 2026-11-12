# 0022 Native packages over SSH and version endpoints

Status: Accepted

## Context
After ADR 0020 Varde reads containers on Docker hosts and the guests of Proxmox, but apps installed
natively in VMs and LXC containers stay invisible, and web services found by the scan carry no
version. Both must stay within ADR 0008: only an exact, comparable version may produce a finding.

## Decision
- **Packages and services over SSH.** A second Ed25519 key, `<data>/ssh/id_ed25519_inventory`, is
  added on the host with `restrict,command="sh -c '…'"`. The forced command is fixed in the binary
  and only reads: `uname -n`, `/etc/os-release`, `dpkg -l`, `rpm -qa`, `apk info -v` and
  `systemctl list-units --type=service`. Whatever the client sends, the host runs only that. A
  separate key is needed because one key line can force only one command, and a host may carry the
  Docker line as well. Host keys are pinned as for Docker over SSH.
- **Only catalog apps are kept.** Packages and services that match no catalog entry are counted,
  not stored. A package name belongs to exactly one catalog app.
- **Distribution packages are not compared.** Distributions backport fixes and keep the upstream
  version (`1.22.1-9+deb12u1` may be fixed while upstream 1.22.1 is affected). A catalog package
  is `distro` by default: identified, version not comparable. Only packages marked `upstream`, from
  the project's own repository, yield a version, optionally through `version_pattern`.
- **Version endpoints.** The catalog may define `version.probe.http`: a documented, unauthenticated
  JSON endpoint, the JSON pointer of the version and `expect` fields that prove the response comes
  from the app (`/ProductName: Jellyfin Server`). After a scan, web services are asked for the
  endpoints of at most three catalog apps whose default port matches or whose name appears in the
  page title; that choice only decides what is asked. A version is recorded only when every
  `expect` field matches; a title or banner never identifies an app. Such a version is `reported`
  and never produces an affected finding on its own (ADR 0023). Requests are GET without
  credentials, through the scope-checked dialer, without redirects, at most 64 KiB, 8 in flight.
- **Proxmox VE as an app.** The version the Proxmox API reports is the `pve-manager` package
  version; Varde records it as that package on the node it talks to, so the catalog entry checks it.

## Alternatives
- Comparing distribution versions with upstream ranges: precise only with the distribution's own
  security data (Debian Security Tracker, OSV distribution ecosystems); a later option.
- An agent or script installed on the host: more data, but software to install and update on every
  host, against ADR 0020.
- Identifying web apps by page title: cheap, but titles are configurable and copied.

## Consequences
Apps whose endpoint carries no product field (Immich, Portainer, Traefik) get no endpoint, and apps
without a public endpoint (Home Assistant, Paperless-ngx, Uptime Kuma) none either. The endpoint
response is not authenticated: a device on the LAN can claim to be an app in any version. The
threat model records this; such a claim can raise a false finding or hide one only for that address.
