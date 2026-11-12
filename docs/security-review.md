# Security review (v1)

A focused review of the code before the first release, done separately from the implementation,
followed by fixes. Scope: authentication and sessions (`internal/auth`, `internal/web`), the REST
API (`internal/api`), the agent channel (`internal/fleet`, `internal/agent`), the feed client
(`internal/feed`), outbound HTTP and the Docker client (`internal/httpx`,
`internal/inventory/docker`). The threat model is `docs/threat-model.md`.

Result: no critical or high findings; one medium and four low findings, all fixed; two
informational notes, one fixed and one accepted.

## Findings and fixes

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| 1 | Medium | Login throttle: the check and the failure count were separate steps. Requests that arrived together all passed the check before the first failure was recorded, and waited in an unbounded queue for the single argon2 slot. A burst bypassed the backoff and could stall every login for minutes. | `Throttle.Begin` checks and reserves the attempt in one step (refunded on success or for non-guesses). Waiting for the hashing slot is capped at 3 s and then answers 503. Used for login, setup, password change and agent enrollment. | `TestThrottleBeginIsAtomic` (200 parallel attempts, 6 pass), `TestThrottleSuccessRefundsIP`, `TestHashingBusyIsBounded` |
| 2 | Low | `safeNext` let control characters through (`/\t/evil.example`); browsers drop the tab and read `//evil.example`. Not reachable at the time, because the login form also lost the return path. | Control characters rejected, path parsed with `url.Parse` and required to be local. The login form now carries the return path, so the feature works. | `TestSafeNext`, `TestLoginReturnsToRequestedPage` |
| 3 | Low | Feed manifest: very large `uncompressed_size` values could overflow the total size check (needs a feed signing key). | Each blob's declared size is bounded before summing. | `TestVerifyManifestStructure` ("size overflow") |
| 4 | Low | API: for session requests without the CSRF header, the form fallback parsed the body before any size limit. | The API caps the body before authentication and authorisation. | `TestSessionCSRFBodyIsBounded` |
| 5 | Low | Agent: a report that passed the certificate check just before a revocation could still write workloads. | `ApplyAgentSnapshot` checks the host state in the same transaction as the write. | `TestSnapshotAfterRevocationIsRefused` |
| 6 | Info | A development feed root only caused a warning; a root rotation could switch to one. | Development roots are refused, initially and in a rotation, unless `VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true`. | `TestDevelopmentRootNeedsOptIn` |
| 7 | Info | On plain HTTP, browsers send no fetch metadata, and an attacker controlling a sibling subdomain (`x.home.lan`) could set the pre-session form cookie for the parent domain and post a login form. | Accepted: the victim would be signed in to an account the attacker already controls; there is no data to steal that way, and HTTPS (with `Sec-Fetch-Site`) removes it. Documented in the threat model. | – |

## Reviewed and found sound

- Every UI route except health, static files, login and setup requires a session; `/metrics`
  requires a token or session; every API route goes through the guard, and read tokens cannot use
  unsafe methods. No GET handler changes state.
- Sessions: new 256-bit IDs on login, setup and password change, stored as hashes, idle and
  absolute expiry, `HttpOnly` and `SameSite=Strict`; a password change ends the user's other
  sessions.
- CSRF: per-session synchronizer token compared in constant time plus fetch metadata and origin
  checks; the relaxation for `Origin: null` without fetch metadata relies on the secret token.
- `X-Forwarded-For` and `X-Forwarded-Proto` are honoured only from configured proxies, using the
  right-most untrusted address.
- Templates use `html/template` only, without `template.HTML`/`template.URL` casts; the CSP has
  no `unsafe-inline` or `unsafe-eval`.
- Setup: the first account and the one-time token are consumed in one transaction.
- Agents: host ID from the server-signed certificate (the CSR subject is ignored), pin and
  revocation checked per request, single-use hashed enrollment tokens, strict bounded payloads,
  per-agent rate limit. The agent pins the CA and requires the server-auth key usage, so a stolen
  agent key cannot impersonate the server.
- Feed: signatures over the received bytes, key IDs bound to keys, roles and validity windows,
  successor-only root updates signed by both thresholds, rollback, reuse and freeze checks
  (including on 304), hash and size before decompression, fetch paths validated against a fixed
  pattern for directories and tarballs, atomic writes.
- Outbound HTTP: HTTPS only, same-host HTTPS redirects capped at three, body limits; the Docker
  client sends only GET and HEAD.

## Checks run for the release state

`go vet`, `go test -race` for all packages, golangci-lint (gosec, staticcheck, revive, errcheck,
govet and others) with no findings, govulncheck (no reachable vulnerabilities; GO-2026-5932 in
`golang.org/x/crypto/openpgp` is not imported), the license header check and actionlint for the
workflows.

## Review of the agentless, version and remediation work (2026-11-09)

Scope: everything from ADR 0023 to ADR 0029 (`1c861e1..` of the main branch history): container file
reads, drift, install and forced commands, service integrations, distribution data, registry tag
lists, update suggestions, VEX, chat channels and the product tour. Independent review of the code,
no external hosts contacted. All findings are fixed with tests that would have caught them.

| Severity | Finding | Fix |
|---|---|---|
| High | Compose labels, which an image can set, reached the copyable update command unquoted: a hostile image could put shell commands into what the admin pastes on the host | Project and service names must follow the Compose grammar or the Compose part is dropped; the service is quoted; paths only when plain; tags and references checked against the OCI grammar |
| Medium | Image package records were read from one container's live file system but applied to every container of the image on every host | Read only from a container whose evidence files are unchanged against the image (change list); otherwise nothing is stored |
| Medium | The install commands cleared the password of an existing account and added it to the docker group; an empty home wrote to `/.ssh` | Account changes only for a user the commands create; subshell; stop on a missing home. Verified on Debian 13, Alpine 3.22 and Fedora 42 |
| Medium | A container could forge the Proxmox node output (other containers, MACs of other machines, an early end) | Command version 2: a per-run nonce drawn on the node marks every node line; host names and MACs from `pct config`; each container once |
| Low | A registry's token realm could point at any https host (blind SSRF) | Realm only on the registry's host or domain or a known token service |
| Low | Traefik pages could add up to about 400 MB | One 16 MB budget for all pages |
| Low | Adding a Fritz!Box had no overall deadline | The same two minutes as a scheduled read |
| Low | The package list cut at 5000 could drop the app manifest | Manifests first, limit 20000 |
| Low | The tour could navigate in a loop after a session expired | Resume only on the step's page and when signed in |
| Low | Discord webhook redaction depended on the exact URL string | Token pattern redacted in any form |

A follow-up from the same review: a package with more distribution records than one osv.dev
answer held never got data; further pages are now read. Documentation corrections: what the
registry is trusted for, notice expansion, the lxc-attach caveat (residual risks).

Checks run afterwards: `go vet`, `go test -race ./...`, golangci-lint v2.15.0 without findings,
govulncheck v1.9.0 (no called vulnerabilities; GO-2026-5932 in `x/crypto/openpgp` not imported),
license headers, image size budget and the hardened smoke test of CI.
