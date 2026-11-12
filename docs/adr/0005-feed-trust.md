# 0005 Feed trust model

Status: Accepted

## Context
The feed decides what the client considers vulnerable. An attacker controlling transport, CDN or a
mirror must not be able to hide advisories (rollback, freeze), inject false ones, or exhaust client
resources. Update-security crypto should not be invented.

The plan was to evaluate `go-tuf` v2 (The Update Framework) first and adopt it if it supports
client-only verification with an embedded root, a static-file layout, consistent snapshots and
bounded resource use; otherwise to implement a minimal signed-manifest scheme.

## Evaluation
`go-tuf` v2 (checked at v2.4.2) meets the functional requirements. Its client, however, pulls in
`sigstore/sigstore`, `sigstore/protobuf-specs`, `google.golang.org/protobuf`, `genproto` and
`google/go-containerregistry`, among others. For a client that verifies static files from one
publisher, that is a large supply-chain and audit surface in a binary that has three runtime
dependencies today. TUF's four roles (root, targets, snapshot, timestamp) also mean four metadata
files to sign and rotate in a pipeline that has one publisher.

## Decision
Implement a minimal signed-manifest scheme with the standard library's Ed25519, following
TUF's ideas where they matter for this threat model:

- A versioned `root.json` lists root and feed keys and thresholds and has an expiry. A new root
  must be the direct successor and be signed by the root threshold of the old and the new root;
  the client walks the chain (`root/<n>.json`) and stores each verified step.
- `manifest.json` (signed by the feed keys) carries a monotonic `sequence`, `created_at`,
  `expires_at` and the content-addressed blobs with sizes and SHA-256.
- Signatures cover the exact bytes received; no canonical JSON is needed.
- Blobs are verified by length and hash before decompression and decompressed with a hard limit.
- Installation is staged and atomic; any failure keeps the previous verified state.

The full scheme, including the threats it does not cover, is in `docs/feed-trust.md`. zstd
decompression uses `github.com/klauspost/compress` (BSD-3-Clause, no further dependencies), since
the standard library has no zstd.

## Alternatives
- go-tuf v2: see above; can be revisited if the feed gets several independent publishers or
  delegations.
- TLS only: no protection against a compromised CDN or mirror.
- Sigstore/cosign signing of an OCI artifact: good for publication, but does not by itself give the
  client freeze and rollback protection for its notion of "current".

## Consequences
- The verification code is small and has no third-party crypto, but it is ours to maintain; the
  test suite covers every rejection path (bad signature, rollback, freeze, hash mismatch,
  decompression bomb, partial download, key rotation, mirror failover, crash during install).
- There is no embedded production root yet because the central feed does not exist. Until it
  does, `VARDE_FEED_ROOT_FILE` supplies the initial root; the official root will be embedded in
  the binary when the feed is published.
