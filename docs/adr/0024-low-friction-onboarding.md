# 0024 Onboarding through few, narrow connections

Status: Accepted

## Context
A homelab has dozens of services. Connecting each one is the reason users give up on inventory
tools; asking for broad access instead (root everywhere, an agent everywhere) is the reason they
should not trust them. Varde needs to see a lot after few steps, while every connection stays
read-only and as narrow as the platform allows.

## Decision
- **One connection, many machines.** Varde suggests the connections that reveal the most first.
  A Proxmox API token shows every node and guest of a cluster; a single key line on a Proxmox node
  reads the packages of all its running LXC containers. Users connect platforms, not services.
- **The containers of a node through one key.** A third Ed25519 key,
  `<data>/ssh/id_ed25519_proxmox`, is added to root's `authorized_keys` on the node with
  `restrict,command="sh -c '…'"`. The forced command lists the containers (`pct list`) and, for each
  running one, prints its host name and network lines from the node's `pct config` and, one file per
  call, `timeout 20 pct exec <vmid> -- cat` of `/etc/os-release`, `/var/lib/dpkg/status` and
  `/lib/apk/db/installed`.
  - A container controls what its `cat` prints. Every line the node adds starts with a nonce drawn
    on the node for this run (`od -N8 /dev/urandom`), so a container cannot forge another
    container, a MAC address, a host name or the end of the output. Host names and MACs come only
    from the node's configuration: a MAC is an identity key that merges records, and a container
    could change its own (version 2 of the command; the first version read them inside the
    container and is no longer accepted).
  - `pct exec` runs `cat` inside the container's namespaces with the container's own rights, so a
    container can only misreport itself. Reading `/proc/<pid>/root/...` from the host was rejected:
    absolute symlinks there resolve against the host, so a container could make root on the node
    read host files such as `/etc/shadow` for Varde.
  - The VMID is checked to be numeric; stopped containers are skipped; the output is capped at
    64 MiB and five minutes and parsed strictly; only packages of catalog apps are stored.
  - Each container becomes a host record that merges with the Proxmox guest through its MAC address.
- **A checklist ranked by what it unlocks.** The overview and the Network page show the next steps
  computed from what Varde knows (networks not allowed, no scan, Proxmox found but not connected,
  containers or Docker hosts nobody reads), ranked by impact. A node of a cluster that is already
  connected is not offered again. Every step states the access Varde gets.
- **Services with read-only credentials only.** Integrations are added where the service offers a
  credential that can only read:
  - Traefik: its API has GET routes only (no credential, or the dashboard's basic auth).
  - Nginx Proxy Manager: a user with the permission Proxy Hosts: View.
  - Fritz!Box: TR-064 `Hosts:1` actions, which a user without any rights may call.
  - OPNsense: an API key of a user holding only Diagnostics: ARP Table and ISC DHCPv4: Leases.

  Routes show which host names point at which machine and whether Varde checks it. Router clients
  become device records with MAC and name, so found devices get names and Proxmox VMs without the
  guest agent get their address through the MAC. https endpoints are pinned by certificate
  fingerprint as for Proxmox; plain http is allowed with a warning on the setup page. Secrets are
  sealed with `integrations.Box`; every connection goes through the scope dialer.
- **Deferred on purpose.** Pi-hole and AdGuard Home offer no read-only credential (an app password
  or user is an administrator); OPNsense with Kea or dnsmasq needs privileges that include writes;
  a Docker TLS client certificate is root on the daemon, as Docker over SSH already is, and adds a
  certificate authority to manage; Caddy's admin API listens on localhost unless a remote mTLS
  listener is set up; Podman's `system dial-stdio` is undocumented. Each is reconsidered when a
  narrow credential exists or can be tested.
- **Relations.** A Proxmox guest records its node; machines show what they run on. Containers keep
  their Compose project and mounts.

## Alternatives
- One key line per container: correct, but exactly the per-service work this decision removes.
- `pct exec` with an inventory script inside each container: needs quoting the forced command
  cannot hold and runs more container code than `cat`.
- Snapshot-based disk inspection: a write on the hypervisor and root on its storage.

## Consequences
The Proxmox key gives whoever controls Varde the package lists of every container on the node,
nothing more; it is still root on the hypervisor, restricted only by the forced command, and the
setup page says so. Each node is connected once; where the cluster shares root's
`authorized_keys` between nodes, one line serves all of them (to be confirmed on a real cluster). VMs still need the package
key per VM or an agent; the guest agent's file and exec calls are not used, because their
permission allows running any command in the guest.
