# 0021 One host record built from the evidence of every source

Status: Accepted

## Context
With network discovery and agentless integrations (ADR 0020) several sources report the same
machine: the scan finds an address, Proxmox reports the guest, Docker over SSH reads the
containers on it, and later an agent or manual entry may add more. Each source stored its own host,
so one machine appeared two or three times, and pages counted hosts, devices and coverage each in
their own way.

## Decision
- **Terms.** A *host* is a machine a platform knows (Proxmox node or guest, Docker host, agent,
  manual entry). A *device* is an address only the scan found. A *workload* is a container, package,
  service or manual entry on one host. A workload is *checked* when it is identified (`exact` or
  `strong`) with a known version; a host is *read* when an active source reports its workloads.
- **Evidence, merged at read time.** The stored hosts and scanned devices stay as they are; they are
  the evidence. `coverage.Machines` merges them into one record per machine whenever a page, the API
  or a counter needs hosts. Records are merged when they share an address inside the allowed
  networks. Two records of the same platform (two Proxmox guests, two agents, a node and its guest)
  are never merged, and an address two such records claim ties nothing together: a shared address
  there means NAT, a VIP or a stale lease. Loopback, link-local and out-of-scope addresses (Docker
  bridges) are ignored. The best source gives the record its ID, name and kind: Proxmox, agent,
  Docker over SSH, local, manual, scan.
- **One place for numbers.** Host counts come from `coverage.CountMachines`, workload coverage from
  `coverage.AssessWorkloads`, finding counts and the overall state from `internal/status`. Pages,
  notices, the API and the metrics use these; templates do not count.
- **State.** A host is `inventoried` while a source that reads workloads reports, `stale` when all of
  them stopped, `paused` when its only such source is a switched-off integration, and `seen`
  otherwise.

## Alternatives
- A persistent merged host table with links: stable IDs across merges, but a migration that rewrites
  host IDs of workloads and findings, and merge decisions that would have to be undone when an
  address moves. Computing the merge is cheap at homelab scale and always reflects the current
  evidence.
- Merging by host name: names differ between sources (`docker-vm` in Proxmox, `docker-vm.lan` in
  reverse DNS) and repeat across networks.

## Consequences
The ID of a merged host is the ID of its best source, so it changes when a better source appears
(for example when Proxmox is connected for a host that was read over SSH). Varde inside a container
only knows its container addresses, not the Docker host's LAN address, so its own host is tied to a
scanned device only when the scan reaches it over a Docker network.
