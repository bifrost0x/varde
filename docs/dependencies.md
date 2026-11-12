# Dependencies

Every third-party component is listed here with a one-line justification and its license. The
version source of truth is `go.mod` / `go.sum`, the `Dockerfile` and the workflow files; versions are
not repeated here.

## Go modules (runtime)

| Module | Why | License |
|---|---|---|
| `modernc.org/sqlite` | Pure-Go SQLite driver (ADR 0002); no CGO. Pinned to a release at least a week old when added | BSD-3-Clause |
| `modernc.org/libc`, `modernc.org/mathutil`, `modernc.org/memory` | Transitive: runtime of the transpiled SQLite | BSD-3-Clause |
| `github.com/google/uuid`, `github.com/dustin/go-humanize`, `github.com/ncruces/go-strftime`, `github.com/remyoudompheng/bigfft`, `github.com/mattn/go-isatty`, `golang.org/x/sys` | Transitive dependencies of the SQLite driver | BSD-3-Clause / MIT |
| `go.yaml.in/yaml/v3` | Catalog source format (YAML). Official successor of `gopkg.in/yaml.v3`; anchors, aliases and merge keys are rejected before decoding | MIT / Apache-2.0 |
| `github.com/klauspost/compress` (only `zstd`) | Decompressing feed blobs; the standard library has no zstd. No further dependencies. Release at least a week old when added | BSD-3-Clause |
| `github.com/gosnmp/gosnmp` | SNMP v2c and v3 (USM with SHA-256 and AES) for reading device descriptions in network scans; no runtime dependencies. Release at least two weeks old when added | BSD-2-Clause |
| `golang.org/x/net` (only `dns/dnsmessage`) | Building and parsing the DNS-SD queries of the local discovery (mDNS); the standard library has no DNS message parser. Part of the Go project | BSD-3-Clause |
| `golang.org/x/crypto` (`argon2`, `ssh`) | Password hashing with argon2id (RFC 9106), and the SSH client for the Docker Engine API over SSH (ADR 0020); the standard library has neither. govulncheck reports GO-2026-5932 for the module's deprecated `openpgp` package, which Varde does not import | BSD-3-Clause |

## Vendored web assets

| File | Why | License |
|---|---|---|
| `internal/web/static/vendor/htmx-2.0.11.min.js` | Partial page updates without a JS build chain (ADR 0007). Copied from the npm release tarball, SHA-256 `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717`; served same-origin under the strict CSP with eval and script-tag processing disabled | 0BSD |

The Docker Engine API is accessed with a small standard-library client instead of
`github.com/moby/moby/client` (ADR 0016).

## Runtime containers (deployment, not shipped in the image)

| Component | Why | License |
|---|---|---|
| `tecnativa/docker-socket-proxy` | Read-only gate in front of the Docker socket (ADR 0006); configuration in `docs/configuration.md` | Apache-2.0 |

## Build and CI tooling (not shipped)

| Component | Why | License |
|---|---|---|
| `golang` container image | Build stage of the Dockerfile | BSD-3-Clause |
| `gcr.io/distroless/static-debian13:nonroot` | Runtime base: CA certificates, tzdata, UID 65532, no shell | Apache-2.0 (image), Debian package licenses |
| `golangci-lint` | Lint aggregator (gosec, staticcheck, revive, errcheck, govet) | GPL-3.0 (tool only, not linked) |
| `golang.org/x/vuln/cmd/govulncheck` | Reachability-aware vulnerability check of the module graph | BSD-3-Clause |
| `actions/checkout`, `actions/setup-go` | Standard GitHub Actions, pinned by commit SHA | MIT |
| `golangci/golangci-lint-action` | Runs golangci-lint with caching, pinned by commit SHA | MIT |
