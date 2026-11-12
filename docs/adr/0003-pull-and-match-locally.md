# 0003 Pull and match locally; no inventory upload

Status: Accepted

## Context
A central service that knows which apps and versions every homelab runs is a ready-made target
list. The feed is small enough (megabytes) to ship to every client.

## Decision
Clients download the complete feed and match locally. No API accepts inventory, no query endpoint
exists, no telemetry is sent.

## Alternatives
- Server-side matching API: less client logic, but leaks inventory and creates a high-value target.
- Private set intersection or k-anonymity lookups: complex, still leak metadata, unnecessary at
  this data volume.

## Consequences
The feed format must be efficient (content-addressed, sharded blobs). Direct mode still reveals
per-app requests to upstreams such as GitHub; this is documented and is the main reason feed mode
becomes the default once it exists.
