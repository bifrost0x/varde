# 0016 Minimal read-only Docker client on the standard library

Status: Accepted

## Context
Varde needs six read-only Engine API calls: `/version`, `/info`, `/containers/json`,
`/containers/{id}/json`, `/images/{id}/json` and the `/events` stream. The official Go client has
moved to `github.com/moby/moby/client` (v0.x at the time of writing) and pulls in a sizeable
dependency tree. ADR 0006 requires that Varde can never issue a write request.

## Decision
A small client in `internal/inventory/docker` built on `net/http`:
- The transport rejects every method other than GET and HEAD before a request leaves the process.
- API version negotiation via `/version`; supported range 1.41 to 1.51, clamped to the daemon's
  range. Responses are decoded leniently, so newer daemons work while they serve that range.
- Object IDs are validated as hex before they are put into a path.
- Response size caps (32 MB for lists, 8 MB otherwise, 1 MB per event line), 30 s request
  timeout, no HTTP proxy, no redirects.
- One container list plus one image inspect per distinct image per sync; image data is cached by
  image ID and the cache is bounded by images in use.

## Alternatives
- `github.com/moby/moby/client`: complete and maintained, but pre-1.0, large transitive surface,
  and its write methods would be one call away.
- Shelling out to the `docker` CLI: needs the CLI in the image and a shell; rejected.

## Consequences
Varde owns a few hundred lines of client code and must follow Engine API changes for the fields
it reads. Those fields have been stable for many API versions. The socket proxy remains the
enforcement point; the client-side restriction is defence in depth.
