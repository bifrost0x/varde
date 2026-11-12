# 0019 Agent protocol details

Status: Accepted

## Context
ADR 0011 fixes the shape: one binary, outbound push over mTLS, one-time enrollment tokens, an
internal CA. Implementing it raised questions the ADR leaves open: how a new agent can trust the
server before it has anything to trust, how certificates rotate without locking an agent out, and
how much data a report carries.

## Decision
- **Server verification by CA pin.** The enrollment token is `varde-enroll-v1.<secret>.<pin>`, where
  the pin is the SHA-256 of the internal CA certificate. The agent accepts the server only if its
  TLS chain contains a CA with that fingerprint and the leaf is signed by it for server
  authentication. Host names are not checked: the server is reached by IP, LAN name or VPN address,
  and the pinned private CA identifies it, as an SSH host key does. No trust on first use, no system
  roots.
- **Client authentication.** TLS 1.3 only. The listener requests a client certificate and verifies it
  against the CA; enrollment is the only endpoint that works without one. On every request the
  server looks up the host named in the certificate and compares the certificate's SHA-256 with the
  pin stored for that host, so a revoked or replaced certificate is rejected on the next request.
  The host ID comes from the certificate, never from the payload.
- **Rotation.** The agent asks for a new certificate (new key, new CSR) when less than 30 days of the
  90 remain. The server stores the new fingerprint as pending and keeps accepting the old one until
  the agent first authenticates with the new one; then the old one is dropped. A crash between
  issuing and saving cannot lock the agent out. The CA itself lives 10 years; rotating it means
  re-enrolling agents (documented, not automated in v1).
- **Reports.** A full container snapshot is sent when it differs from the last accepted one (SHA-256
  over the sorted snapshot); otherwise only a heartbeat with the hash. If the server does not hold
  that hash (for example after restoring a backup), it asks for the full snapshot. The server
  computes the difference itself (the same `ApplySnapshot` as for local Docker), so the agent keeps
  no diff state that could drift. Snapshots are small (a few kB per container), so a full
  snapshot on change replaces the originally planned diffs.
- **Liveness.** Agents announce their interval; a host that misses three becomes `stale` and raises
  a system notice for the daily digest. Notices are separate from findings and never P1.

## Alternatives
- Public PKI or ACME for the listener: needs a public name and outbound access for every homelab.
- Trust on first use: silently trusts whoever answers first.
- Diff protocol: less data on large hosts, but needs sequence numbers and resync handling for little
  gain at homelab scale.

## Consequences
- The CA key in `/data/ca/ca.key` is the most sensitive file of the installation; backups must treat
  it like a password store.
- Losing the CA means re-enrolling all agents; losing an agent's data volume means enrolling that
  agent again with a new token.
