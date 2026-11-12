<!-- SPDX-License-Identifier: Apache-2.0 -->

# Recognition corpus

Ground truth for `internal/eval` (ADR 0023). `go test ./internal/eval` runs Varde's recognition on
every case and fails when a number falls below `../gate.yaml`. `make eval` writes the report.

## Files

- `containers.yaml`: real images. Digests and labels were read from the registries on 2026-11-09
  with `docker buildx imagetools inspect` (Docker Hub through `mirror.gcr.io`, same digests).
- `synthetic.yaml`: cases the real images do not show, each with `why`: conflicting sources, user
  pins, topologies of hosts and devices, package lists, advisory matching.
- `inventory-*.txt`: real output of Varde's SSH inventory command in Debian trixie, Fedora 42 and
  Alpine 3.22 containers.

## Truth basis

| Basis | Meaning |
|---|---|
| `tag` | A pinned version tag; the publisher builds that release under it. |
| `label` | The publisher's version label on a floating tag. |
| `label+rel` | The label, and the same version is the project's latest release, found independently (catalog research, a live version endpoint). |
| `user` | The user stated the version (`varde.version`). |
| `registry` | The registry gives a version tag the same digest as the running image (recorded in `registry_tag`). |
| `package` | An upstream package of the app in the image's package database (recorded in `packages`). |
| `manifest` | The app's own `package.json` in the image's working directory or its parent (recorded in `packages` with `manager: npm` and `path`). |
| `none` | Nothing states the version reliably. Varde must report none; any version counts as wrong. Such cases also lower version coverage, because the app does run some version. |

## Adding a case

- Record real data; never copy Varde's output as truth.
- State the basis and, where it is not obvious, a `note`.
- A new catalog entry needs at least one case (`TestEveryCatalogAppHasACase`).
- When recognition improves, raise `../gate.yaml` in the same change; never lower it to pass.

## Distribution packages

`distro.yaml` matches distribution packages against real per-CVE records from osv.dev
(`distro-records.json`). Reduce a record to the entries of the package and release it tests, keep its
ID, `modified`, `upstream` and ranges unchanged, and state the read date.
