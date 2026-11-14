# Catalog

The catalog describes self-hosted apps: how to recognise them, how to read their running version
and where their security advisories are published. It is the core asset of Varde and is
community-maintained. Data license: Apache-2.0 (ADR 0015).

One file per app: `catalog/apps/<id>.yaml`. The schema is enforced by `internal/catalog`
(authoritative) and described for editors in `catalog/schema.json`. CI loads every entry.

## Example

```yaml
id: immich
name: Immich
homepage: https://immich.app
tags: [photos, media]
images:
  - match: ghcr.io/immich-app/immich-server
  - match: altran1502/immich-server
    note: legacy name, last published 2022
oci_source:
  - https://github.com/immich-app/immich
version:
  scheme: semver
  sources:
    - label: org.opencontainers.image.version
    - tag: '^v?(?P<v>\d+\.\d+\.\d+)$'
advisories:
  coverage: full
  github_repos:
    - immich-app/immich
exposure_hints:
  default_ports: [2283]
  typical: public
maintainers_of_entry: [bifrost0x]
verified: 2026-11-08
```

## Fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable slug `^[a-z0-9][a-z0-9-]{0,63}$`. Never reused, never renamed (use `aliases`). |
| `aliases` | no | Former IDs of this app. |
| `name` | yes | Display name. |
| `homepage` | yes | `https://` URL. |
| `tags` | no | Lowercase keywords. |
| `images[].match` | at least one of `images`, `oci_source`, `packages`, `services` | Image repository without tag or digest, lowercase, fully qualified or Docker Hub short form (`jellyfin/jellyfin`, `library/nginx`). No wildcards. |
| `images[].flavor` | no | `lsio` for linuxserver.io images (enables the `lsio` version normaliser). |
| `images[].note` | no | Free text, e.g. "legacy name". |
| `oci_source` | no | Values of the `org.opencontainers.image.source` label that identify the app (`https://github.com/org/repo`, no trailing slash, no `.git`). |
| `packages[]` | no | `{manager: dpkg|rpm|apk, name: <package>}` for native installs, read over SSH or by agents. A package name belongs to exactly one app. |
| `packages[].versioning` | no | `upstream` when the package comes from the project's own repository and its version is the release version; `distro` (default) for distribution packages. Distributions backport fixes without changing the upstream version, so a `distro` package is never compared with upstream advisory ranges; on Debian, Ubuntu and Alpine it is checked against the distribution's own security data (ADR 0028). |
| `eol` | no | Product name on endoflife.date (`nginx`, `proxmox-ve`); the inventory then marks versions on unsupported release lines (ADR 0029). Only names endoflife.date lists. |
| `packages[].source` | no | Source package name the distribution's security data uses, when it differs from the package name (`openssh` for `openssh-server`). Default: the package name. |
| `packages[].version_pattern` | no | Regex with the named group `v` that extracts the release version from the package version (`^(?P<v>\d+\.\d+\.\d+)\+` for `10.11.2+deb13`). Default: the version without epoch and revision. |
| `services[]` | no | `{unit: <systemd unit name>}`, exact name; weaker than packages and without a version. |
| `version.scheme` | yes | `semver` (dotted numeric, 1 to 5 components, optional pre-release) or `calver` (`YYYY.M[.x]`). |
| `version.sources[]` | no | Ordered extraction chain, first usable hit wins. Each item is exactly one of `label: <image label key>` or `tag: <regex>`; a regex must contain the named group `v`. Optional `normaliser: lsio` on an item. Default chain: `org.opencontainers.image.version` label, then a tag matching the scheme. |
| `version.probe.http` | no | The app's own version endpoint, asked after a network scan (ADR 0022). `path`: a documented endpoint that needs no login; `json_pointer`: RFC 6901 pointer to the version string (empty: the response is a JSON string); `version_pattern`: optional regex with group `v`; `expect`: one to four `pointer: value` pairs that prove the response comes from the app (a product name, not a format); `check_path`: optional second endpoint where `expect` is checked, for apps whose version endpoint has no product field. Never a page title or banner. |
| `version.normalise.strip_prefix` | no | Prefix removed from extracted versions (default `v`). |
| `advisories.coverage` | yes | `full`: the project publishes advisories in a structured, machine-readable way (GitHub repository advisories, OSV). `partial`: some advisories are structured, others only in release notes or CVE databases. `limited`: no structured advisories; Varde relies on CVE databases (NVD via CPE) and its own pipeline. |
| `advisories.github_repos` | no | `owner/repo` with GitHub repository security advisories. List every repository the project actually publishes in (sibling repos included). |
| `advisories.packages[]` | no | `{name, ecosystem?}` filter for multi-product repositories: only affected packages with a matching name (and ecosystem, if given) apply to this app. Entries without a package name apply only when the advisory names no package at all. Empty means every affected package applies, except those whose name proves another project: a module path (`gitea.com/gitea/runner`) or an `owner/name` reference (`louislam/dockge`) that neither lies below the app's repositories, images and `osv_packages` nor carries one of its names. An advisory that names only such packages is unverified. Free-text names always apply, so list the app's packages here when a repository publishes for several products under plain names. |
| `advisories.osv_packages[]` | no | `{ecosystem, name}` as used by OSV (`Go`, `npm`, `PyPI`, ...). |
| `advisories.cpe` | no | CPE 2.3 prefixes for NVD/EUVD matching, `cpe:2.3:a:<vendor>:<product>`. |
| `advisories.notes` | no | Where else advisories appear (mailing list, blog, release notes). |
| `exposure_hints.default_ports` | no | Container ports the app listens on. |
| `exposure_hints.typical` | no | `public`, `lan` or `internal`. Only a weak tie-breaker. |
| `maintainers_of_entry` | yes | GitHub handles responsible for the entry. |
| `verified` | yes | Date (`YYYY-MM-DD`) the entry was last checked against the live project. |

## Derived entries

For images the catalog does not know, Varde makes local entries on every analysis (ADR 0025, ADR
0038). Per image, in this order:

1. **The image's source label.** `org.opencontainers.image.source` names a GitHub repository whose
   name matches the image name. This is the publisher's own statement: confirmed.
2. **The first-party index** (`docs/configuration.md`). It ships with Varde and rests on what
   projects and registries state. Two kinds of evidence confirm, as does one that agrees with the
   image's source label or with its path on GitHub's registry. One alone is a report and does not
   alert until the user confirms the app with `varde.app`. A source label that names anything
   else overrules the index.
3. **GitHub's registry.** `ghcr.io/<owner>/<repo>` is taken for `github.com/<owner>/<repo>`. This is
   a guess (packages are often named differently from their repository): recognised, never
   confirmed on its own.

Confirmation is kept per image: an image with one statement stays unconfirmed beside a confirmed
image of the same project, and an image that only inherited a source label from its base image
is not confirmed by it. A derived entry reads that repository's advisories, uses the default
version chain and the registry, and is marked "recognised automatically" with its basis. A
reviewed entry here always replaces it, so a derived app is a good candidate for a catalog
contribution.

## Rules

- Verify every value against the live project: registry, image labels, the GitHub security tab.
  Do not guess. Record the check date in `verified`.
- An image repository belongs to exactly one app. CI rejects duplicates.
- Images under `lscr.io/linuxserver/<x>` are listed once; `ghcr.io/linuxserver/<x>` and
  `linuxserver/<x>` are recognised as the same repository.
- Floating tags (`latest`, `stable`, `release`, `main`, `nightly`, `develop`, ...) never yield a
  version. If an image only ships floating tags, document how users can pin a version (OCI label,
  `varde.version` container label).
- Every entry needs a case in the recognition corpus (`internal/eval/testdata/corpus`, see its
  README) with real data and a stated truth basis; CI fails otherwise.
- A version endpoint is added only when its response names the product; record the source file in
  `docs/catalog-evidence/`. A package is `upstream` only when it comes from the project's own
  repository and its name is not also a distribution package.
- Apps without structured advisories are still listed. Use `coverage: limited` and fill in every
  source that exists (`cpe`, `osv_packages`, `notes`); never mark an app as covered when it is not.

## Container labels users can set

| Label | Effect |
|---|---|
| `varde.app=<id>` | Identifies the container as catalog app `<id>` (overrides everything). |
| `varde.version=<v>` | Running version (overrides every other version source). |
| `varde.exposure=public\|lan\|internal` | Exposure, overrides detection. |
