# 0032 Every installed package is checked against its distribution's security data

Status: Accepted

## Context
Since ADR 0030 Varde keeps the full package list of every host, and the agent (ADR 0031) delivers it
for every Linux host. Only the packages of catalog apps were checked, though: on a typical server a
dozen of several hundred. The operating system itself (OpenSSL, OpenSSH, glibc, the kernel tools)
stayed unchecked, which is where most security updates of a Linux host land. Distribution security
data (Debian, Ubuntu, Alpine per-CVE records; AlmaLinux, Rocky Linux and openSUSE notices) knows
every backported fix (ADR 0028), and osv.dev serves it.

## Decision
- **System packages.** Every source package of a host on a release with distribution security data
  becomes a system package: a package workload marked `system`, one per source package, at the
  highest version among its binary packages. Builds from outside the distribution (`~bookworm`,
  `.ngx`) and source packages a catalog app covers already are left out. System packages are part
  of the system's package list; they are neither apps nor gaps and do not appear in those lists.
- **Identified as themselves.** A system package needs no catalog entry. Its app ID is
  `os:<ecosystem>/<source package>`; the matcher compares its version with the distribution's
  records in the package manager's order, as for catalog apps.
- **osv.dev decides which records apply.** One batch query per 500 packages asks osv.dev which
  records affect each package at its installed version; follow-up pages are asked for. Varde
  downloads only those records, at most 3000 per refresh and eight at a time, keeps them until
  their modification time changes, and drops the records of packages no longer installed. Entries
  the distribution rates as no security problem for it (Debian's `unimportant`) are dropped.
- **Only what an update fixes is a finding.** A system package finding needs a fixed version in
  the distribution's record that is newer than the installed one; its action is "update the
  package". Issues the distribution has not fixed yet are not findings: on a Debian release they
  number in the hundreds and would bury the actionable ones. Their number is kept per package
  (migration 0018) and shown on the system's page as "without fix", without notifying.
  Priorities follow the usual rules: without CVSS a finding is P3 (weekly digest), a known
  exploited one (CISA KEV) P1.
- **Same switch as osv.dev.** The check is switched with the OSV source: it tells osv.dev the
  names, versions and releases of the installed packages. The getting-started guide asks for it
  with this explanation.

## Consequences
- With an agent or a package reader on a host, Varde reports the security updates of the whole
  system, not only of its apps, each with the version that fixes it.
- A first check of many hosts downloads a few thousand records and completes over a few refreshes;
  later refreshes download only changed records.
- Unfixed issues are counted per package on the system's page; they notify only once an update
  fixes them, as findings.
- In feed mode system packages are not checked yet: the feed carries records for catalog apps only.
