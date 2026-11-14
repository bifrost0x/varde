# 0041 Release tags in the data package

Status: Accepted (the builder's tag reads, the blob, the installation's store and the update
target are built; the package carries the blob from the next build)

## Context
An update is only worth naming when it can be installed. Varde took the version to update to
from the advisories alone: the lowest fixed version that fixes the most. Projects name fixed
versions that were never published in the form a user runs (a skipped patch release, an image
that only exists for the next one), and an installation could check a tag against the registry
only with registry versions switched on, which asks the registry about the images it runs. In
the default setup every suggested image line carried the remark that Varde had not seen the tag.

The package builder already lists the tags of every image it reads a release from (ADR 0040) and
kept only the newest. A tag list costs one request and no pull, so it is not bound to the budget
of the release package lists, which reaches a few dozen images a day.

## Decision
- **The daily build reads the release tags of every catalog image.** For each image of a
  reviewed or generated entry whose version chain reads a tag, `cmd/packagebuilder` lists the
  repository's tags and keeps those the entry's tag rule reads a release from, newest release
  first, at most 600. Floating tags, branches and commit tags are not among them. The read runs
  before the release package lists and ends at the same deadline (`-releases-until`).
- **Kept between builds.** A list stands for 20 hours in the builder's store. One that cannot be
  read again, or that the registry cuts short, ships as stored for up to 14 days: an old list
  still names releases that exist and only misses the newest. An image without a release tag
  ships no line.
- **A blob of its own.** `tags` holds one JSON line per image: app, image, read time and the
  tags. Older installations skip the blob. A malformed line refuses the package like any other
  malformed blob.
- **One store for both origins.** An installation keeps the lists in the table that registry
  versions fills (ADR 0029). A list from the package replaces what is stored only when it is
  newer or the stored answer is a failed read, so the fresher of the two stands, and a
  repository the package knows is not asked again that day. The lists stay when the package is
  left: a tag that existed still exists.
- **The update target is a release that exists.** With the releases of a container's image
  known, each fixed version an advisory names is replaced by the lowest release at or above it
  before the target is chosen. A fixed version above every known release stays as named: the
  list may be a day behind the fix. A pre-release counts only for a running pre-release. What a
  finding says about its own advisory (`fixed in`) is unchanged.
- **The inventory names the newest release.** Where a known release is above the version a
  container runs, the list of apps and containers says so. With registry versions switched
  on, the installation lists the tags of every identified container's repository that the
  package brought no fresh list for, those with open findings first; the setting says so.
- **No new request from an installation.** Everything above comes with the package (ADR 0039).

## Alternatives
- Listing tags inside the release reads: bound to their manifest budget, so most images would
  have none. Rejected.
- Versions instead of tags in the blob: the installation needs the tag to write the image line,
  and reads the version from it with the entry's own rule. Rejected.
- GitHub releases as the list: they say what the project released, not what the image
  repository holds. The generator's check C4 already ties the two.

## Consequences
- Update suggestions name a tag the registry lists without registry versions switched on, for
  every image of the catalog.
- A registry lists tags in no order a client can choose (ghcr.io: oldest first), so the newest
  releases of a repository with tens of thousands of build tags are on the last pages. The
  builder therefore reads a tag list to its end, up to a hundred thousand tags, and keeps the
  newest 600 releases; the release package lists use the same client and reach those images
  too. An installation's own registry reads keep the bound of ten thousand.
- The lists are the base for further checks that need to know which versions exist, such as
  doubting an advisory whose fixed versions were never releases of the app.
