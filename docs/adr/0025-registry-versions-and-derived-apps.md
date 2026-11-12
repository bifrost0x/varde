# 0025 Versions from the registry and apps derived from source labels

Status: Accepted

## Context
The first measurement (ADR 0023) found a quarter of the apps running floating tags (`latest`,
`stable`, `release`) without a version label: Varde knew the app but not the version. And every app
needed a reviewed catalog entry before Varde recognised it at all, so coverage could only grow as
fast as the catalog. Recognition must keep up with new releases and new apps on its own.

## Decision
- **Floating tags resolve through the registry.** A container's registry digest is immutable. Varde
  lists the tags of the image's repository (OCI distribution API, at most 10 pages of 1000), keeps
  the tags that name a release of the app, and asks the newest 25 for their digest with `HEAD`
  requests (which Docker Hub does not count as pulls). The tag whose manifest has the running digest
  is the running release. It becomes evidence like a label (`registry: tag X points to the running
  image`) and, being the publisher's own tag, is confirmed unless another source disagrees. Image
  variants (`2.1.2-alpine`, `-ls4`) are the same release; pre-releases (`-rc1`, `-beta`) are not.
- Requests are anonymous and read-only: a bearer challenge is answered with a token for
  `repository:<name>:pull`; links in the tag list are followed only on the same registry. Answers
  are cached per digest: a found tag is kept, a miss is asked again after a day. At most ten
  images per half hour.
- **Off by default.** It is a new outbound connection; the registry learns which images run, as it
  does on every pull. The setting is under Settings; the next steps suggest it when containers on
  floating tags lack a version.
- **Unknown apps are derived from their source label.** For a container whose image the catalog
  does not know, Varde makes a provisional, local entry from `org.opencontainers.image.source` when
  it points to a GitHub repository and the image name matches the repository name
  (`ghcr.io/homarr-labs/homarr` and `github.com/homarr-labs/homarr`). Labels are inherited from base
  images; the name match keeps an image built `FROM nginx` from becoming nginx. The entry reads the
  repository's security advisories, and its version comes from labels, tags or the registry. Entries
  are recomputed on every analysis; a reviewed catalog entry with the same source always wins.
- **Derived apps do not alert on their own.** Their findings are `unverified` with the reason until
  the user confirms the app with `varde.app=<id>`; the inventory marks them "recognised
  automatically" and offers the catalog suggestion.

## Alternatives
- Pulling images to read versions from their content: real pulls, rate limits, disk; kept for
  images without a release tag (next stage: targeted file reads).
- A central digest-to-version index in the feed: the better long-term source (no per-installation
  registry traffic), planned with the feed pipeline; the local resolver stays for private images.
- Deriving apps from any label: false identifications through inherited base image labels.

## Consequences
In the corpus, version coverage rose from 75 % to 89 % with no wrong version, and an app not in the
catalog (Grafana) is recognised with its version. Images whose release tags all differ from the
running digest (rebuilt floating tags, private registries without anonymous access) stay unknown.
With an egress allowlist, the registry hosts (`registry-1.docker.io`, `auth.docker.io`, `ghcr.io`,
`lscr.io`, …) must be allowed.
