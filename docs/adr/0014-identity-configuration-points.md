# 0014 Product identity configuration points

Status: Accepted. Namespace: `bifrost0x/varde` for the repository, the Go module path and the image names.

## Context
The product name and namespace must live in exactly one place per artefact type, so a later move
(for example to a dedicated `varde` organisation) stays mechanical.

## Decision
| Artefact | Single point |
|---|---|
| Name, env/label prefix, repo URL, User-Agent | `internal/buildinfo` constants |
| Go module path | `go.mod` (see below) |
| Local image name | `IMAGE` in `Makefile` |
| CI and release image names | `IMAGE_NAME` / `DOCKERHUB_IMAGE` and `GHCR_IMAGE` in each workflow's `env` |
| UI product name | `buildinfo.Product`, passed to templates |

The Go module path is inherently repeated in every import. A namespace change is mechanical:
`go mod edit -module <new>`, rewrite import paths, update the `-X` ldflags in `Makefile` and
`Dockerfile`, and the `goimports.local-prefixes` lint setting.

## Alternatives
- Vanity import path served from a project domain: decouples the module path from the GitHub
  namespace permanently. Worth doing if a domain is secured; requires a static `go-import` page.

## Consequences
Moving the namespace after the first release breaks `go install` paths and image references for
existing users; it would need a deprecation period with images published under both names.
