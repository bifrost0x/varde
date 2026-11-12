# 0011 One binary, two modes; agents push over mTLS

Status: Accepted

## Context
Homelabs grow to several Docker hosts and VMs. Pull-based agents would require inbound ports on every
monitored host.

## Decision
The same binary runs as `varde server` or `varde agent`. Agents connect outbound to a dedicated
server listener (default 8443) and push inventory. Enrollment uses a short-lived, single-use token;
the agent generates its key and sends a CSR, the server signs it from an internal CA whose key never
leaves `/data`. Afterwards mTLS only, per-host certificate pinning, immediate revocation, automatic
rotation (default lifetime 90 days).

## Alternatives
- Separate agent binary: a second artefact to build, sign and audit.
- SSH-based collection from the server: the server would need credentials for every host.
- Pre-shared bearer tokens: simpler, but long-lived secrets without per-host key binding.

## Consequences
The server owns a small CA; its key is a high-value asset in the threat model. The agent listener is
separate from the UI so it can be exposed to other VLANs without exposing the UI.
