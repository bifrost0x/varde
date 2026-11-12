# 0034 Attack paths tell exploitable findings from background noise

Status: Accepted

## Context
With system packages (ADR 0032) and image packages (ADR 0033), a homelab easily has hundreds of
open findings. Severity and exposure (ADR 0005) rank them one by one, but they do not say which
of them an attacker can actually use, or what one finding leads to: a remote flaw in a public
container is far worse when the container runs privileged on an LXC guest whose Proxmox node has
an unpatched kernel. Equally, a CVSS 9.8 flaw in CUPS on a server where CUPS only listens on
loopback is noise. Varde has the facts to tell these apart, scattered over its sources: proxy
routes, the network scan, the sockets hosts listen on, container settings, the Proxmox topology
and the attack vector of each advisory.

## Decision
- **Facts collected for it.** The inventory command (version 3) reads the listening sockets from
  `/proc/net/{tcp,tcp6,udp,udp6}` (migration 0021). The Docker collector keeps the settings that
  decide what a container can do on its host (privileged, added capabilities, host network and
  process namespace, user, devices, mounts), read once per container. Distribution records
  without a severity take the CVSS vectors of their CVE from osv.dev, so the attack vector
  (network, adjacent, local, physical) is known for package findings.
- **Paths are built on every analysis run** (`internal/paths`). An entry is the internet (a
  container or machine behind a proxy route under a public domain, the proxy itself) or the LAN
  (a scanned or listening service, a container with published ports). A service leads to the
  findings it can expose: the container's app and the network libraries of its image; on a host,
  the source packages that commonly serve the port (or the one the scan's banner names) and the
  libraries they link, as indirect evidence. A flaw is usable from the internet only with a
  network vector, from the LAN also with an adjacent one; an unknown vector is assumed remote and
  marked. A service that grants control without authentication (an open Docker API) is a
  foothold by itself. From a foothold the path continues: out of the container through a
  privileged setting, a mounted Docker socket or the host's root, or through a local kernel flaw;
  to root through a local flaw; from an LXC guest to its Proxmox node through the node's kernel;
  to other containers on a shared Docker network; from a machine taken from the internet to the
  LAN services of others. A path is a way in, not a flaw: each step uses the strongest flaw at
  that point and keeps the others as alternatives, which are on the path too and must all be
  fixed to cut it. Detours through containers the entry reaches directly are left out. Depth and
  count are bounded (two lateral hops, 200 paths); a path is scored by its entry, its weakest
  required step (KEV, CVSS, EPSS), what it reaches (a hypervisor, a machine, a container) and its
  length, and names the fix that cuts it first.
- **Every finding gets a place with a reason**: on a path from the internet or the LAN, an
  amplifier (a local flaw that turns a foothold on a path into root), background noise, or
  unclear. Noise needs a known reason: physical access only; a local flaw on a machine no path
  reaches; a container nothing reaches; a package no listening service of the host uses. Without
  the data (no listening sockets, an unknown exposure, the bound reached) a finding stays unclear,
  never noise.
- **Priorities follow the place.** A finding on a path from the internet is P1 when known
  exploited or CVSS 7 or more, else at least P2; on a path from the LAN or an amplifier at least
  P2; noise P3 (P2 when known exploited). Unclear findings keep the matrix's priority. Noise
  therefore never notifies immediately.
- **Shown in the UI and messages.** "Attack paths" lists the paths step by step with the fix that
  cuts each; "Background noise" lists the noise grouped by reason. Findings carry a badge and a
  filter, the finding page names its paths and its place, the overview shows the top three, and
  notifications say when a finding is on a path. Stored per run (migration 0022).

## Consequences
- The ranking matches how an attack works: the few findings that open a way in come first, the
  long tail of unreachable package flaws stops alerting while staying listed.
- The analysis is a model, not a proof. Varde cannot see router port forwards, firewalls or what
  an app does with a library; the port-to-package map and library lists are heuristics, and a
  path through a library is marked indirect. A wrong "noise" needs a known reason, which keeps
  that error rare and visible.
- Reachability depends on data the user turns on: listening sockets come with agents and SSH
  inventories, routes with proxy integrations and public domains, services with the network scan.
  Without them most findings stay unclear, as before.

## Amendment: what counts as a reason
A review against common homelab layouts tightened the rules for noise. Reachability comes from
more than published ports: a container in the host's network or in another container's network
(`network_mode: service:gluetun`) is reached like that network, and a port bound to a LAN or
Tailscale address is reachable, not loopback. A host listening on a port Varde cannot tie to a
package or a container is missing data: its packages stay unclear. A container next to a reverse
proxy or a tunnel (cloudflared) may be forwarded to and stays unclear until the proxy's routes are
read. Containers past the depth bound stay unclear. Paths are explored up to 5,000 and the 200 most
dangerous are kept, whatever order they were found in, so the result is the same on every run. A
known exploited flaw is never lowered by its place, except one that needs physical access.
