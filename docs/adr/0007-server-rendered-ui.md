# 0007 Server-rendered UI: html/template, htmx, hand-written CSS

Status: Accepted

## Context
The UI is mostly lists, detail views and a few forms. A strict CSP and a small attack surface are
requirements; a Node build chain would add a large supply chain for little benefit.

## Decision
Go `html/template`, htmx for partial updates, hand-written CSS built on design tokens (0013). All
assets are embedded via `go:embed`; no CDN, no external fonts, no inline scripts or styles.

## Alternatives
- SPA (React, Svelte): richer client state, but a Node toolchain, larger bundle, a JSON API for
  every view and a harder CSP.
- Pure server rendering without htmx: simpler, but full page reloads for every action.

## Consequences
CSP `default-src 'self'` without `unsafe-inline` is achievable. htmx is vendored as a single file
with its version and checksum recorded in `docs/dependencies.md`. If a required interaction cannot be
built this way, the maintainer decides on the deviation.
