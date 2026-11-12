# 0036 Wider detection: language packages, more distributions, appliances, local discovery

Status: Accepted

## Context
Images and hosts in a homelab hold more than Varde read: Python, PHP, Ruby, .NET, Java and Rust
packages of self-hosted apps; images built on Wolfi, Chainguard, openSUSE Tumbleweed or Red Hat
UBI; appliances whose own operating system is the thing to update (Synology DSM, QNAP QTS,
TrueNAS, Unraid, Home Assistant OS); and devices with no TCP port the scan probes (printers,
speakers, smart home devices). Each gap left systems looking clean that are not.

## Decision
- **Language packages in images.** The reader (format 3) streams `/usr/local/lib`,
  `/usr/local/bundle`, `/opt`, `/app`, `/srv`, `/var/www` and the image's working directory and
  keeps only package metadata: Python `METADATA`/`PKG-INFO` under site- or dist-packages, Composer's
  `installed.json`, gem specifications, `*.deps.json`, and `pom.properties` inside JARs (nested
  jars one level deep). Rust programs built with cargo-auditable are read from `/usr/local/bin`.
  The distribution's own `/usr/lib` is left out: those files belong to its package manager. One
  image reads at most 1 GiB in four minutes; a read that stops at a bound is marked partial
  (migration 0028) and missing packages of it are not counted as removed.
- **Matching.** The packages are checked in their OSV ecosystems (PyPI, Packagist, RubyGems,
  NuGet, Maven, crates.io) with each ecosystem's version order (PEP 440, Maven, RubyGems, NuGet,
  Composer, SemVer), one finding per package of an advisory.
- **Distributions.** Wolfi and Chainguard (apk), openSUSE Tumbleweed and Red Hat Enterprise
  Linux including UBI (rpm). osv.dev keeps Red Hat's data per repository, which a package list
  does not name; baseos, appstream and crb all apply. Fedora, CentOS Stream, Arch and SLES have no
  usable per-package data on osv.dev and stay unchecked, saying so.
- **Appliances.** Integrations read the system's own version (DSM through SYNO.DSM.Info with a
  user without admin rights; QNAP's sign-in page without a credential; TrueNAS with a read-only
  API key; Unraid's API; Home Assistant Core through `/api/config`) and record it as a system with
  a `firmware` package, which catalog entries check against advisories like Proxmox's
  pve-manager. The scan offers the matching integration on devices it recognises.
- **Docker from its own repositories.** `docker-ce` and `containerd.io` from download.docker.com
  carry the release in their version and are not covered by the distributions' data; catalog
  entries check them against the Go vulnerability database and the projects' advisories.
- **Network devices.** The Fritz!Box integration also reads FRITZ!OS through TR-064 DeviceInfo
  (where the box allows it to a user without rights), and every UniFi access point, switch and
  gateway with a firmware version becomes a system of its own with a firmware package. Vendor
  advisories for these are rarely machine-readable; the versions are recorded so that curated
  data can check them.
- **SNMP.** With a v2c community or a v3 user (SHA-256, AES) in the environment, scans read the
  system description and name of devices that answered, which names switches, UPS, printers and
  NAS.
- **Local discovery.** Every scan asks each address by unicast DNS-SD (port 5353) and SSDP (port
  1900) and the local segment once by multicast; devices are named by the service types or the
  UPnP model they announce. Many responders, routers among them, answer only multicast, which
  reaches devices only when Varde runs on the LAN segment (a binary, or a container with host
  networking).

## Consequences
- Image reads take longer for images with large site-packages or many JARs; they run once per
  image and week.
- Appliance advisories mostly come from NVD records, whose version notation differs per vendor;
  the versions Varde records follow each vendor's advisories.
- Firmware of routers, switches and access points is recorded and named, but most of it has no
  machine-readable advisories; curated vendor data (ADR 0037) is what checks it.
