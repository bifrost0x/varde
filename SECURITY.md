# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting:
**Security > Report a vulnerability** in this repository. Do not open public issues, discussions or
pull requests for security problems.

Include the affected version (`varde version`), the mode (server, agent, direct, feed), a
description of the impact and steps to reproduce. Redact inventory data, hostnames and secrets.

You can expect an acknowledgement within 7 days and an assessment within 14 days. Fixes are
released as soon as practical; reporters are credited in the advisory unless they prefer otherwise.

## Scope

In scope: the `varde` binary and container image (server and agent mode), the feed client and its
trust model, the seed catalog, the deployment examples in `deploy/`, and the CI/release workflows
of this repository.

Out of scope: vulnerabilities in third-party apps that Varde reports on (report those upstream),
and findings that require an already compromised Docker host or a deliberately weakened deployment
(e.g. `VARDE_ALLOW_DIRECT_SOCKET=true` combined with a compromised container).

## Supported versions

Before 1.0, only the latest release receives security fixes.

## Design notes

The security model is described in [docs/threat-model.md](docs/threat-model.md). Key properties:
read-only Docker access through a socket proxy, no inventory ever leaves the installation, no
telemetry, signed feed data, hardened non-root container.
