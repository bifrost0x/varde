# 0038 Look up instead of guess, and one installation for free and paid use

Status: Accepted (stage 1 built; stages 2 to 4 planned)

## Context
Coverage grew by adding things one at a time: a catalog entry per app, an integration per
appliance, curated advisories per vendor. That cannot reach what homelabs actually run. At the same
time the free, standalone installation is the product: one container, no service of the project
needed. A paid data feed (ADR 0037) may come later, but must not make the free installation
heavier, and switching between the two must not need a second image or a new deployment.

## Decision
- **Look up, do not guess.** Everything in a homelab arrived through a delivery channel (image
  registries, package repositories, app stores, release pages, firmware update servers). A tool
  crawls the channels and compiles an index from exact keys (image repository and digest, package
  and version, source repository, vendor ID with model and firmware version) to products, source
  repositories and advisories. The installation reduces what it observes to such keys and looks
  them up in its local copy. An exact match needs no confidence score, which keeps ADR 0008.
- **The source repository is the universal key for software.** It joins what images, packages and
  app stores state with what GitHub advisories, OSV git ranges and CVE references state.
- **Devices are identified by what their firmware states, never by names a user can set.** Host
  names, UPnP friendly names, mDNS instance names and SNMP `sysName` are display data only.
- **The free index needs no server.** A scheduled CI job builds it weekly from a tool in this
  repository and publishes it signed; every release embeds the index of its build date. The
  built-in catalog stays as reviewed refinement and wins where both exist.
- **One installation, one switch.** The uplink is switched on under Settings with a license; the
  running container changes its data source and falls back on its own when the license ends
  (`internal/uplink`). `VARDE_MODE` in the environment fixes the mode as before and locks the
  switch. Until the service exists, releases carry no trust root for it and the section says "not
  available in this build"; development roots make the whole path testable.

## Stages
1. The uplink switch (built): license documents, root roles `license` and `override`, unknown
   roles ignored, runtime switching of the advisory sources, the settings section.
2. Software (built). The first-party index, `index/images.tsv`, embedded in the binary. A
   builder visits candidate projects once, centrally, and keeps an image only on a first-party
   statement: the project's README or Compose file names it, its Docker Hub page links the
   project, or it is in the owner's namespace on GitHub's registry together with the README.
   Public app store lists (Unraid Community Applications, Umbrel) and GitHub's topic search only
   say where to look. The first table (2026-11-11) has 1811 images, 1107 of them confirmed by two
   kinds of evidence. A README alone counts only in the owner's namespace, and the namespace on
   GitHub's registry only for an image named like the repository: a first build without these
   rules tied sidecars and companion projects to the wrong repository. Still planned: advisories
   from CVE references and OSV git ranges.

   **An installation downloads nothing to recognise apps.** An earlier form of this stage (2a)
   let each installation download the app store lists itself, as an optional setting. It was
   withdrawn before release: recognition must not cost users traffic or depend on third-party
   lists at run time. The lists' knowledge reaches users only as pointers for the central
   builder. The index also arrives in the daily data package, as one signed blob beside the
   advisories (ADR 0039, `docs/data-package.md`): that is the one
   download, the same for every installation, and it replaces the per-app queries rather than
   adding to them.
3. Devices: self-description readers, devices as systems with a firmware package.
4. The uplink service (ADR 0037).

## Free and paid: the same knowledge
What Varde knows to recognise software and to find its vulnerabilities is the same in the free
installation and with the paid uplink: the catalog, the index and the advisory data. Nothing of it
is held back for subscribers. The uplink differs in how often data is updated and in further
services around it (decided 2026-11-11). This replaces the split in ADR 0037 where curated data
was a subscription benefit; ADR 0037 is revised when the feed is built.

## Alternatives
- A larger fingerprint database (banners, signatures): the approach of existing scanners; needs a
  signature per product and trades precision for coverage.
- Guessing a CPE from banners at the installation: fuzzy, and against ADR 0008.
- A second image or a build flag for the paid variant: two things to deploy and to test.

## Consequences
- Automatically recognised apps alert when the publisher's own source label (with a matching
  image name) names the repository, when the index holds two kinds of evidence, or when one kind
  agrees with the label or with the image's path on GitHub's registry; one kind alone, or the
  registry path alone, yields `unverified` (changes ADR 0025 for the confirmed cases). The registry
  path is a guess: in the lists' own data, about one in six `ghcr.io/<owner>/<name>` images
  belongs to a repository of another name. Images on GitHub's registry without a source label
  are now recognised this way, unconfirmed.
- Recognition through the index is not yet in the measured corpus: its cases need real registry
  data recorded for images outside the catalog. Until then the corpus covers the label and
  registry bases only.
- The free index is signed with a single CI key, weaker than the uplink's builders, and says so.
- What came through no channel stays a coverage finding (ADR 0012).
- Automatic license renewal and revocation arrive with the service.

## Amendment (2026-11-12): entries for index images
Index images without a reviewed entry get a generated one, built and checked in the daily data
build and ranked below reviewed entries (ADR 0040).
