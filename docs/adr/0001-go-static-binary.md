# 0001 Go, single static binary

Status: Accepted

## Context
Varde runs on homelab hardware (x86 mini PCs, Raspberry Pi, NAS). It must be small, portable to
amd64 and arm64, cheap to audit and easy to sign.

## Decision
Go, one binary built with `CGO_ENABLED=0`, `-trimpath`, fixed ldflags. Standard library first;
every third-party module is justified in `docs/dependencies.md`.

## Alternatives
- Rust: comparable footprint, slower iteration, weaker fit with the maintainer's other projects.
- Python/Node: far larger runtime and dependency tree, harder to harden and to ship on a
  distroless static base.

## Consequences
Cross-compilation is trivial; the image is a distroless static base plus one file. Any dependency
that needs CGO (e.g. the C SQLite library) is excluded by construction.
