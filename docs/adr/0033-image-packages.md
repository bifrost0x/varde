# 0033 The packages of container images are checked, also through agents

Status: Accepted

## Context
ADR 0026 lets Varde read the package databases of the images its containers run, through the
Docker archive endpoint, to tell an app's version. Only Varde itself read them (local Docker,
Docker over SSH), and only to identify catalog apps. Agents, the way most hosts are read since ADR
0031, did not read images at all. The base layers of images are where most container
vulnerabilities live: an image built months ago carries the OpenSSL and glibc of that day, and
ADR 0032 already knows how to check such packages against their distribution's data.

## Decision
- **Image packages are checked like system packages.** The source packages of each container's
  image, on a release with distribution security data, are matched against the distribution's
  records (ADR 0032) and reported on the container, one finding per advisory. Only what a fixed
  version addresses is a finding, and its action is a newer image, not a package update inside
  the container, which a recreate would undo.
- **Agents read their images.** The agent runs the same image package reader as Varde, against
  its own Docker socket, when the server's "Read the package lists of images" setting is on; the
  report answer carries the setting. Reads are queued and sent with the next report, at most 50
  per report.
- **An agent speaks only for its own images.** The server stores an image record from an agent
  only for an image that one of the agent's own active containers uses, after storing the
  containers of the same report. It never replaces a successful record another source made: an
  image record now carries its source (empty for Varde's own reads, `agent:<host ID>` for an
  agent; migration 0019), and an agent may replace only its own records or failed reads. Records
  are checked strictly (image ID form, release fields, field lengths, at most 20,000 packages).
- **One switch for the data.** The source packages of images join the system packages in the
  osv.dev batch queries (ADR 0032), under the same switch.

## Consequences
- With agents and the osv.dev switch on, Varde reports the vulnerabilities of image base layers
  with the fixed version, grouped per package and version across the containers that share an
  image.
- A compromised agent can misreport the packages of images only it uses; other hosts' images and
  Varde's own reads stay as they were. Its own containers' findings it can hide anyway, by lying
  about them.
- Old images produce many findings at once; digests group them (one block per package and
  version), priorities follow the usual rules. Issues no image fixes yet are counted on the
  container, as for host packages.

## Amendment: one record per source
A review found that "an agent speaks only for its own images" did not hold: image IDs of public
images are predictable, so an agent could claim another host's image and, writing first, decide
what every container of that image was checked against. Image records are now kept per source
(migration 0023): Varde's own read and each agent's. A container is checked against Varde's own
read of its image, or else the record of the agent on its own host, never another agent's. A
revoked agent's records are deleted.
