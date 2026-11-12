# 0030 The full inventory of hosts and guests

Status: Accepted

## Context
Varde read every package of a host but kept only the few that belong to a catalog app; the rest
was counted and discarded. VMs were seen only from the outside through the Proxmox API, and the
Docker containers inside them stayed invisible unless each VM got its own SSH connection. A user
with a Proxmox node, a handful of VMs and LXC containers saw machines, not what runs on them, and
could not tell what was installed, where the information came from, or what was missing.

## Decision
- **Keep every package.** The full package list of a host is stored (table `host_packages`,
  migration 0017), with name, version, manager, release and the source package it was built from,
  which distribution security data names. Catalog apps still become workloads for identification
  and matching; the list itself is the inventory.
- **Inventory command version 2** reads the package databases themselves: `/var/lib/dpkg/status`,
  `/lib/apk/db/installed` and `rpm -qa` with `%{SOURCERPM}`, instead of `dpkg -l` and `apk info`,
  which carry no source package. Output of version 1 is still read.
- **One key on the Proxmox node reads every guest (node command version 3).** For each running
  LXC container through `pct exec`, and for each running VM whose QEMU guest agent answers through
  `qm guest exec`, the node reads `/etc/os-release`, the dpkg, apk and rpm databases, and
  `docker ps` and `docker image ls`. Names and MAC addresses come from the node's `pct config` and
  `qm config`. A VM becomes a host record that merges with the Proxmox guest by MAC; its Docker
  containers become container workloads, identified like those of a Docker host (image, tag, the
  registry digest from the image list, Compose labels). A VM whose agent does not answer is recorded
  with the step that enables it.
- **The trust model stays.** Every line the node adds carries the run's nonce (ADR 0024); guest
  agent answers are JSON strings, so nothing a VM prints can become a marker. Every call reads
  `/dev/null`: `pct exec` reads its input and, inside the `while read` loop, consumed the rest of
  the guest list, so only the first guest was read on a real node. Each call has a timeout; the
  whole run is bounded to 15 minutes and 128 MB.
- **A page per system** (`/systems/{id}`) shows what Varde knows about one machine: the sources
  that report it, the guests on a node, the apps with the source of their versions, every
  container, every installed package (filterable), the open findings, and what Varde cannot see
  yet with the step that changes it.

## Consequences
- With the node key, a Proxmox node with its LXC containers and agent-enabled VMs is inventoried
  completely, including the Docker containers inside the VMs, without one connection per guest.
- `qm guest exec` runs the fixed commands as root inside the VM through the agent. The key line
  forces the command, so a stolen key yields these lists and nothing else; the threat model says
  so.
- Docker containers read through the guest agent have no image labels (`docker ps` does not show
  them), so versions come from tags and the registry; Docker over SSH reads more.
- The vulnerabilities of all packages, not only of catalog apps, are matched in the next step;
  the inventory comes first.
