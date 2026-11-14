# 0044 Security fixes named only in release notes

Status: Accepted (the builder's reads, the records in the package and the installation's
handling are built; the package carries the records from the next build)

## Context
Many projects publish part of their flaws as repository advisories and fix the rest with a line
in the release notes ("Security: fix a path traversal in the file API", "fixes CVE-2026-1234").
Every app derived from an image's source label or from the index has coverage `partial` for
that reason, and the Gaps page tells the user that such fixes are missed. The NVD helps only
where someone filed a CVE with a usable CPE (ADR 0042).

Asking a project's releases from each installation would tell GitHub which apps run there and
adds nothing the builder cannot ask once for everyone (ADR 0039).

## Decision
- **The builder reads the release notes.** After the repository advisories, `cmd/packagebuilder`
  asks GitHub for the newest 50 releases of every repository whose apps do not all have
  `coverage: full`, with conditional requests and the same interval as the advisories. A
  repository whose catalog entry says its advisories are complete is not asked: its notes add
  nothing but repetition.
- **A release counts when its notes say so.** A line of the release name or body names a
  security fix when it carries a CVE or GHSA ID, a heading "Security", or wording such as
  "security fix", "vulnerability", "XSS", "path traversal" or "remote code execution". A
  dependency bump never counts: its CVE belongs to the dependency, which the image's own
  package and library checks cover. Drafts and pre-releases are skipped, and so is a release
  whose tag is not a plain version (`1.4.2`, `v1.4.2`).
- **One record per flaw.** Each CVE or GHSA ID a release names becomes a record of its own with
  that ID as its alias; a release without one gives one record. The record says that versions
  before the release lack the fix (`introduced 0`, `fixed` the release), quotes the lines that
  named it, links the release and carries the origin `release`. An ID the repository already
  published as an advisory is not repeated.
- **Never "affected".** The range is marked inferred (`varde_inferred`): the notes say where a
  fix landed, not since when a flaw existed, and a keyword is not an advisory. A running
  version below the release is a finding to check yourself, with the release as the version
  that fixes it; it is not prioritised and does not notify. Installations released before this
  decision already treat an inferred range so.
- **Ranked last.** Within a flaw, the project's advisory, osv.dev and the NVD decide before a
  release note; the note only stands where nothing else describes the flaw. A version at or
  above the release is not cleared by the note: it only says where one fix landed, so it never
  outvotes another record that leaves the version uncertain, nor a note of a fix on another
  release line.
- **Never fatal.** A rate limit or an error stops the reads for this build and leaves what
  earlier builds stored; the summary says so and counts the repositories whose read failed. The repositories not reached are read first by
  the next build.

## Alternatives
- Direct queries from each installation, on by default: they reveal the inventory to GitHub
  and repeat one request per installation that the builder makes once. Rejected.
- Findings that count as affected for a CVE named in the notes: the notes do not say since when
  the flaw exists, and a CVE in a release note of an app sometimes belongs to something the app
  ships. Rejected while nothing measures the precision.
- Reading CHANGELOG files in the repository: no common form, and most projects that keep one
  also copy it into their releases. Left for later.

## Consequences
- Apps with `partial` or `limited` coverage that publish their fixes in release notes get a
  "check yourself" finding for each security release above the running version, with the
  release to update to and the lines that named it.
- The first builds add up to one request per repository; conditional answers cost nothing
  against GitHub's limit afterwards. Until every repository was read once, the notes of the
  ones not reached are missing.
- The wording is a heuristic. A release that mentions security without fixing anything gives a
  finding to check; a fix described without any of the words is missed as before.
