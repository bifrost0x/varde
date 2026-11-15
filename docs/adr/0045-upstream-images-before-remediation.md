# 0045 An image is suggested only when it is known to fix something

Status: Accepted

## Context
A container with flawed packages in its image got the card "Pull a newer image and recreate the
container" and, with one package known to be exploited, the state "Update now". In the lab,
CyberChef (`latest`) and Immich machine learning (`3.4.1`) both carried that card while no newer
image existed upstream: the distribution had shipped the fixes, the publishers had not rebuilt
their images yet. Pulling changed nothing. The card asked for something that could not be done,
in the most urgent state there is.

Three things caused it. The action followed from the findings alone (image findings exist, so
pull a newer image); Varde never asked whether a newer image exists and whether it fixes them. A
KEV entry on any package of the image made the finding P1 (ADR 0034 only lowered it for
background noise), and "reachable in your network" meant that the container publishes a port,
not that the flawed package serves it. And the card's state followed the priority alone.

## Decision
- **An upstream status for every container with image findings.** The analysis decides one of
  `update_available` (a newer image fixes at least one finding), `update_no_effect` (a newer
  image exists but fixes none), `no_upstream_fix` (the running image is the newest of its tag) or
  `unknown` with the reason. It is stored per container (table `upstream_status`, migration 0035)
  and read by the pages and the notifications. An update is suggested only for
  `update_available`; every other status says so and names no image.
- **Where the answer comes from.** First the registry's answer about the running image, then the
  data package's read of the newest release (ADR 0039), whose index digest also tells that the
  container runs that release. An image without a registry digest (built locally, never pulled)
  or pinned by digest is `unknown`; so is everything when registry checks are off and the data
  package says nothing.
- **Asking the registry.** With registry versions on (ADR 0025, off by default), a checker asks for
  each running image (repository, tag, digest, platform): a `HEAD` request for the running tag,
  whose digest differs when a floating tag was rebuilt, and, for a version tag, the newest tag on
  its track from the stored or listed tags: the same prefix and image variant (`-alpine` stays
  `-alpine`, `-cuda` stays `-cuda`), the same major version (and minor below 1.0) unless the user
  allows more, no pre-release unless one runs. Answers stand for `VARDE_UPSTREAM_TTL` (6 h), ten
  images per run, every half hour. A failure (401, 403, 429, timeout, an authentication scheme
  other than an anonymous bearer token) is recorded with its reason and is never an answer.
  Answers of images no container runs any more are pruned.
- **Knowing what a newer image fixes.** A newer image is judged by its package list with the same
  matcher and records as the running one: fixed, remaining, unclear, and flaws it introduces
  (shown, never hidden). The list comes from the data package when it read that image, or, with
  the separate switch **Read newer images from the registry** (off by default), from a read of the
  image in the registry with the release reader of the data build (ADR 0039): manifests, config
  and layers squashed in memory, at most two images per run and 1 GB each, layer reads cached.
  Nothing is pulled into Docker, nothing is recreated. A newer image Varde has not read stays
  `unknown` with "a newer image exists, but Varde has not read what it fixes".
- **The card's state is a table.** `upstream.Decide` maps the urgency of the card (P1 to P3, or
  unconfirmed) and what the one update does to its most pressing findings (fixes one, fixes only
  others, fixes nothing) to a state. "Update now" needs both: urgency and an update that fixes an
  urgent finding. Urgency without one is the new state **Mitigate now**, which notifies at once
  as before, with guidance instead of an update: limit who can reach it (when it is reachable), a
  Dockerfile that builds the image again with the distribution's package updates, or a snooze
  until a fixed image appears (at most 180 days; findings fixed by a newer image reopen by
  themselves). Serious and minor findings keep "update soon" and "next update"; their card says
  when no fixed image exists.
- **Reachability per component.** A finding in an image package is urgent only when the package
  serves what the container exposes: the program the container runs (from the container's
  command, kept since this decision, with wrappers such as `tini`, `sh -c` and `*.sh` entrypoints
  skipped) or a library such a program commonly loads (`openssl`, `glibc`, `zlib`, ...), in a
  container reachable from outside its host. The lists are data
  (`internal/paths/components.yaml`). Without a known command, or for any other package, the
  label is "in the image" and the priority at most P2. The card names the component: "known-
  exploited flaw in openssl, served on port 8080", or "known-exploited flaw in busybox, in the
  image".

## Alternatives
- Reading newer images in every installation by default: a few hundred megabytes per candidate,
  and Docker Hub counts manifest requests as pulls. The data package already reads the newest
  release of every catalog app once for everyone; the local read stays a switch.
- File ownership from the package databases (dpkg `.list` files, apk `R:` lines) to tie the
  command's executable to its package: more exact, but it needs a second read of every image and
  a larger record. The program's name and the list of programs cover the common servers; a
  program Varde does not know leaves its packages "in the image", which errs on the quiet side.
- Calling every urgent finding without a fix "update now" with a different text: the bucket's name
  is a promise; it must hold.

## Consequences
- CyberChef `latest` with a KEV in a bundled tool and the tag pointing to the running image is
  "update soon" with "No fixed image upstream yet" and the reason "known-exploited flaw in
  <package>, in the image". With the KEV in openssl it is "Mitigate now", notified at once, with
  the mitigation steps.
- Immich machine learning `3.4.1` without a published port and without a newer tag on its track
  is at most "update soon", with no image to pull.
- With registry checks off (the default), containers the data package does not cover show their
  image findings as "Varde cannot tell whether a fixed image exists" and point to the setting.
- Containers read before this decision have no command until their next inventory read; until
  then their image packages are "in the image".
- Private registries without credentials stay `unknown`.
