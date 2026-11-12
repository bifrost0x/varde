# 0028 Distribution security data and VEX

Status: Accepted

## Context
Distributions backport fixes into their packages without changing the upstream version: Debian 12
ships nginx `1.22.1-9+deb12u8` with fixes that upstream released in 1.29. Comparing such a package
with upstream ranges raises false alarms, so until now Varde identified distribution packages of
catalog apps but never compared their versions (ADR 0008); every advisory stayed unverified. Hosts
and LXC containers in a homelab often run their services from distribution packages. Debian,
Ubuntu and Alpine publish which package version in which release fixes each CVE; osv.dev serves
this data in the OSV format, with versions in the package manager's own form.

## Decision
- **Distribution packages are matched against their distribution's records.** A package of a
  catalog app with `versioning: distro` on a release Varde knows (`debian-12` → `Debian:12`,
  `ubuntu-24.04` → `Ubuntu:24.04:LTS`, `alpine-3.22.1` → `Alpine:v3.22`, `almalinux-9.8` →
  `AlmaLinux:9`, `rocky-9.3` → `Rocky Linux:9`, `opensuse-leap-15.6` → `openSUSE:Leap 15.6`) is
  checked against the
  records of its source package in that release (catalog `source`, default the package name). The
  versions are compared in the order of dpkg, apk or rpm (`internal/version/distro.go`). The record of
  the distribution decides for its package: patched means not affected, even when an upstream
  range says otherwise. An advisory the distribution has no record of stays unverified, as before.
- **Per-CVE records** (`DEBIAN-CVE-…`, `UBUNTU-CVE-…`, `ALPINE-CVE-…`) are stored for Debian,
  Ubuntu and Alpine. They name their CVE in the OSV `upstream` field, which joins them to the CVE's
  other advisories. Their notices (DSA, DLA, USN) list several CVEs and would merge findings; they
  carry the same versions and are not stored.
- **Notices, expanded per CVE**, for AlmaLinux, Rocky Linux and openSUSE, which publish nothing
  else (ALSA, RLSA, SUSE-SU). When matched, a notice becomes one record per CVE, named by the CVE
  and linking the notice. The notice is not an alias, which would merge the CVEs again. Several
  notices can cover one CVE (module streams); one that finds the package affected wins.
- **RPM epochs.** The inventory key line reads `%{EPOCHNUM}` since this change; package lists from
  key lines set up before carry no epoch, and the epoch is then left out on both sides. Within a
  release a package keeps its epoch, so the order holds. RHEL's data is split by repository
  (baseos, appstream), which a package list does not tell, and Fedora has no data on osv.dev; both
  stay not comparable.
- An unfixed record is affected without a fixed version. Debian rates some issues `unimportant`
  for a package and does not fix them; those stay unverified, visible but never alerting.
- **Vendor builds are left out.** Packages from a project's own repository carry the release
  codename (`1.28.0-1~bookworm`), backports `~bpo12`; on AlmaLinux and Rocky, distribution builds
  name the enterprise release (`el9`, `module_el9.7.0`) and vendor builds add their own tag
  (`.el9.ngx`). The distribution's data does not cover them, so they stay not comparable.
- **Fetching.** The records come from osv.dev (`querybatch` for the present (release, source
  package) pairs of an app, then each new or modified record). Each stored record keeps only the
  entries of the queried releases, plus a mark of the queried set, so a host on a new release
  refetches the record. Further pages are read (at most 20 per package); a page token that does not advance is refused rather than stored incomplete. At most 600
  records per refresh. When an app has no distribution package any more, its records are removed.
- **One consent with OSV.** The queries reveal package names and releases to osv.dev, as the OSV
  source reveals package names, so they run under the same switch (`DIRECT_OSV`, off by default).
  While it is off and distribution packages are present, the next steps suggest it.
- **VEX export.** `GET /api/v1/vex` returns an OpenVEX 0.2.0 document of the open findings: each
  workload is a product (its package URL when known). An affected finding becomes `affected`, with
  the fixing update as action. An unverified one becomes `under_investigation` with its reason. A
  suppressed one becomes `not_affected`, with the operator's reason as impact statement. The CVE
  names the vulnerability where one is known. The document ID is derived from the statements, so
  an unchanged state gives the same ID. Varde states only what it established; it does not claim
  `fixed` or `not_affected` on its own.

## Consequences
- In the corpus, real Debian 12 and Alpine 3.22 records for nginx produce no findings for patched
  packages and the right ones for older packages. An upstream range of the same CVE does not
  count. Live against osv.dev, 102 nginx records gave the same result.
- New catalog entry nginx with Debian and Alpine packages; Mosquitto gains its distribution
  packages.
- In the corpus, a real AlmaLinux 9 notice covering four CVEs gives four findings before the fix
  and none after it, also when read without epoch.
- Hosts set up with the earlier key line read RPM versions without epoch until step 3 of the setup
  is run again.
- Not covered: RHEL and Fedora (see above); container
  image packages (the app's version comes from the image); Debian testing and Alpine edge, which
  have no release number. "Match confidence" as its own measure was not added: trust (ADR 0023)
  and the unverified state already carry it.
