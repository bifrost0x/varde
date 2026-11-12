# 0012 Coverage as a product feature

Status: Accepted

## Context
Varde cannot guarantee that it sees everything. Silent blind spots would make "all clear"
misleading.

## Decision
Every independent source of "what exists" (reverse proxy routes, Proxmox guests, DHCP clients, the
Docker inventory itself) is reconciled against identified workloads. Gaps are coverage findings,
separate from security findings and never P1. A public route without an identified workload is the
highest-ranked coverage finding.

## Alternatives
- Report only what is identified: simpler, but overstates safety.

## Consequences
The overview shows coverage numbers next to the status. Coverage sources are pluggable and
read-only.
