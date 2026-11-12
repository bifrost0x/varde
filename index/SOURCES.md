# Sources of the first-party index

`images.tsv` maps image repositories to the GitHub repositories of their projects. It is built by
`cmd/indexbuilder` (`make index-fetch index`), reviewed like any other change, and embedded in the
binary. The daily data package (`docs/data-package.md`) carries the table `main` holds, so an
installation that reads the package gets new rows without a Varde update. An installation never
fetches lists or pages for it.

## What a row rests on

The third column names the evidence. Every kind is a statement of the project or of the registry:

| Kind | Statement |
|---|---|
| `readme` | The repository's README or root Compose file names the image as something to run (`docker pull`, `docker run`, `image:`). Alone it counts only for an image in the repository owner's namespace: Compose files name what a project runs beside itself, companion projects name the image they extend, and forks copy a README. |
| `hub` | The image's description on Docker Hub links the repository. |
| `ghcr` | The image is in the repository owner's namespace on GitHub's registry and is named like the repository (`immich-server` for `immich`). Never alone, and never for a differently named image: a sidecar in the owner's namespace is not the project. |

Two kinds confirm a row (its findings alert); one is a report (findings are shown as unverified).
An image several repositories claim goes to the one with the most kinds and is dropped on a tie.
Official Docker Hub images, helper images and placeholder names of examples (`owner/...`,
`yourusername/...`) are never listed. `index.Check` verifies these rules for the embedded table
at build time.

## What a row does not promise

A row names the repository that publishes the image. For a repackaged app that is the packaging
repository (`binhex/arch-plex`), which rarely publishes the advisories of the app inside: such an
image is recognised, but only advisories of the packaging repository are read.

## Where the builder looks

Pointers say where to look and are never evidence: the public app store lists of Unraid Community
Applications and Umbrel, and GitHub's repository search by topic. A pair a pointer states enters
the table only when one of the statements above confirms it.

Pages read, all public, with anonymous GET requests: `raw.githubusercontent.com/<owner>/<name>/HEAD/`
(`README.md`, `readme.md`, `docker-compose.yml`, `compose.yaml`) and
`hub.docker.com/v2/repositories/<namespace>/<name>/`.

## This table

Built on 2026-11-11 from pages fetched that day, with the app store lists as the only pointers:
2821 pointers, 2641 repositories visited, 2576 with a README or Compose file, 1480 Docker Hub pages
read, 9729 requests. 173 pages were not available to this build, so some rows lack `hub` evidence
they would otherwise have. This section describes the first table; the weekly rebuild reports
its numbers in its pull request.

1811 images, 1107 confirmed by two kinds of evidence (730 `ghcr,readme`, 377 `hub,readme`), 704
reported (387 `readme`, 317 `hub`). Dropped: 454 with the registry namespace alone, 311 named only
by another project, 2 claimed by several repositories with equal evidence.
