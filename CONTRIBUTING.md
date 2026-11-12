# Contributing

## Ground rules

- Precision over recall. Changes that increase alert volume need a strong argument and tests.
- No telemetry, no tracking, no calls to new external services without discussion in an issue.
- Standard library first. New dependencies need a justification in
  [docs/dependencies.md](docs/dependencies.md) and an Apache-2.0 compatible license.
- Significant design changes get an ADR in [docs/adr/](docs/adr/).

## Development

Requirements: Go (version in `go.mod`), Docker, `golangci-lint` v2, `make`.

```sh
make test           # go test -race ./...
make lint           # golangci-lint
make vuln           # govulncheck
make license-check  # SPDX headers
make fuzz           # short fuzz run over all Fuzz* targets
make image          # container image
make run-dev        # local server on 127.0.0.1:8080
```

`make check` runs everything CI runs except the image build.

## Code

- Every source file starts with `// SPDX-License-Identifier: Apache-2.0` (or the equivalent comment
  syntax).
- `context.Context` first, errors wrapped with context, structured logging via `log/slog`.
- Packages live under `internal/`; interfaces are defined by the consuming package.
- Tests are part of the change. Parsers and matchers get fuzz tests.

## Commits and pull requests

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, `ci:`, `chore:`).
- Small, focused pull requests. CI must be green.
- By contributing you agree that your contribution is licensed under Apache-2.0.

## What never goes into this repository

Everything pushed here is public at once: commits, their messages, pull request texts, review
comments and CI logs. So:

- No keys, tokens, passwords, environment files, databases or other local state.
  `scripts/check-tracked-files.sh` runs in CI and fails when such a file is tracked; `.gitignore`
  lists them. The private keys of the data package never leave the maintainer's machines and the
  repository's secret store (`docs/data-package.md`).
- No inventory exports, hostnames, addresses or screenshots of a real installation. Test data
  comes from throwaway containers and public images.
- No working notes, plans or session links of coding assistants, in files or in commit
  messages. The decisions belong in an ADR; the rest stays out.
- No details of a vulnerability in released code before it is fixed. Report it privately
  (`SECURITY.md`); the fix is prepared in a private security advisory, not in a public pull
  request.

## Catalog entries

The catalog contribution guide lives in [docs/catalog.md](docs/catalog.md). Every entry must be verified against the live project: image names, advisory
repositories and version labels. Do not guess.
