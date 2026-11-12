# 0020 Agentless first: network discovery and official integrations

Status: Accepted

## Context
ADR 0011 made an agent the way to cover further hosts. In practice users install one Varde and
expect it to see their network: Proxmox nodes and guests, Docker hosts, appliances. Requiring an
agent on every machine is the opposite of a low-friction homelab tool. The agent stays useful where
Varde cannot reach a host (another VLAN, behind a VPN), but it must not be required.

## Decision
- **Network scope.** The user allows network ranges (private ranges only: RFC 1918, 100.64/10,
  IPv6 ULA; at most 8 ranges, IPv4 scans up to a /20). Every connection Varde makes into the local
  network, for scans and for integrations, goes through one dialer that checks the resolved address
  against the scope. A host name that resolves outside the scope is refused.
- **Discovery scan.** Started by the user. TCP connects to a short list of homelab ports, bounded
  (64 in flight, 300 new connections per second, 0.8 s connect timeout). Varde reads what services
  announce on their own (SSH greeting, page title, server header, certificate issuer, the
  unauthenticated Docker `/version`) and sends nothing else. A port that answers on more than 60 %
  of the addresses is treated as intercepted (a router redirecting DNS, a transparent proxy) and
  ignored. Reverse names come from the DNS servers found in the scan, at most two. Scan results are
  never the basis for a security finding.
- **Official interfaces only.** Each platform is read through what it documents for this purpose:
  - Proxmox VE: the REST API with an API token of a user holding the `PVEAuditor` role. The server
    certificate is pinned by its SHA-256 fingerprint, which the user confirms; the check also runs
    for resumed TLS sessions.
  - Docker: the Engine API over SSH, as `docker -H ssh://` does it: the remote side runs
    `docker system dial-stdio`. Varde has one Ed25519 key; the user adds it with
    `restrict,command="docker system dial-stdio"`, so it opens no shell and forwards nothing. The
    host key is fetched with Ed25519 preferred, confirmed by the user and pinned; later connections
    accept only that key type. The read-only Docker client (ADR 0016) is reused unchanged.
- **Modular.** Each integration is a row with its own enable switch; disabled integrations do not
  run. Removing one deletes the hosts it reported with their workloads and findings.
- **Secrets.** API token secrets are sealed with AES-256-GCM, bound to the integration ID, under a key
  in `<data>/keys` separate from the database. The SSH private key lives in `<data>/ssh` (mode 0600).

## Alternatives
- Mandatory agent (ADR 0011 as the only path): rejected as the default; kept as an option.
- Docker API over plain TCP through a published socket proxy: no authentication, and it exposes
  container environment variables (often secrets) to the whole network.
- Docker over TLS with client certificates: official as well, but needs daemon reconfiguration and a
  CA on every host; planned as an additional option.
- ICMP or ARP discovery: needs raw sockets (capabilities the container drops) and does not cross
  routed VLANs.
- Active version probing of discovered web services: deferred at first; added with catalog-defined
  version endpoints only (ADR 0022).

## Consequences
Varde now holds credentials for other systems. Read-only roles bound the damage of a compromise, but
the Docker key grants Docker API access, which equals root on that host; the setup page says so.
Behind Docker Desktop, refused connections arrive as timeouts, so hosts without any open probed port
are not found there; on a Linux Docker host they are. The threat model covers the new trust boundary.
