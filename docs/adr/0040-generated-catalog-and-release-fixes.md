# 0040 Generated catalog entries and release fixes

Status: Accepted (the generator, the release reads, the display and the weekly check are built;
the package carries the new blobs from the next build)

## Context
The reviewed catalog holds a few dozen apps, the index (ADR 0038) well over a thousand images.
For an image without a reviewed entry Varde derives one at runtime from labels and the index, and
that entry has no tag rule and no version scheme beyond the guess. Two questions stay open for
most containers: which tags are releases and what version they stand for, and whether a newer
release of the image fixes the flaws found in its packages. The second one is what a user asks
when a container shows dozens of findings in image packages.

The constraints are those of ADR 0039: installations make no new outbound requests, everything
that decides what is vulnerable is signed, and what Varde knows does not depend on paying. A
reviewed entry costs a person time, so the reviewed catalog cannot grow to the index's size.

## Decision
- **The daily build generates catalog entries.** For index images without a reviewed entry,
  `cmd/packagebuilder` writes an entry (name, homepage, images, source repository, a version
  scheme and one tag rule) and ships it in a new blob `generated`. Entries are ordered by weight
  (Docker Hub pull count, else the number of kinds of evidence in the index row). A build checks
  at most 150 new candidates and rechecks entries whose inputs changed; the rest waits for the
  next day. A shipped entry is rechecked at least every 30 days and dropped when it fails or
  when no check could confirm it for twice that time.
- **Six checks, all of which must pass.** C1: the entry is valid and claims nothing a reviewed
  entry claims (id, alias, image, source, repository). C2: the index ties every image to the
  repository by first-party evidence, by the rule of ADR 0038 for a confirmed match. C3: the tag
  rule matches at least three tags that are GitHub releases and no floating tag (`latest`,
  `edge`, `nightly`, `main`, a hash), and the newest matching tag resolves to a digest. C4: the
  newest tag is on the line of the newest GitHub release (same major.minor; equal for date
  versions). C5: a CPE, if one is set, exists in NVD and NVD ties it to the repository; a CPE is
  only set that way. C6: the entry changes what an installation finds only through the version,
  which equals what the registry resolution yields for the same digest, and through a CPE that
  passed C5; no case of the evaluation corpus gets worse. A failing candidate is recorded with
  the first check it failed.
- **Fixed rules, no free-form patterns.** The tag rule comes from a fixed set of templates
  (`v?X.Y.Z`, `X.Y.Z`, `v?X.Y`, each with the variant suffix reviewed entries use, and date tags
  `YYYY.MM.DD`). The narrowest template that passes C3 wins.
- **Generated is weaker than reviewed.** Coverage is at most `partial`, the maintainer of the
  entry is `generator`, and an entry that claims more is dropped. The installation takes the
  precedence reviewed (builtin or feed catalog), then generated, then derived. A generated entry
  whose id, alias, image, source, package or unit a reviewed entry already claims is left out,
  and its id equals the derived id, so what an installation stored under it stays valid. An
  image the generator could not check is read as derived, with derived's advisory sources and no
  CPE.
- **No human review of generated entries.** Decision of the maintainer: an entry that passes all
  six checks goes live. The audit trail is a readable list, not a pull request: the build writes
  `catalog/generated.json` (every entry with its check results) and `catalog/generated.md`
  (counts, and new, changed and dropped entries against the previous build) onto the branch
  `data` and keeps both for 90 days as an artifact of the workflow run.
- **Release package lists.** For every catalog entry with a confirmed tag rule, the build reads
  the newest release's image from the registry, linux/amd64 and linux/arm64, newest layer first,
  until the package databases are found, with the file rules of the image reader. Layers are
  cached by digest in the builder's store, so shared base layers are read once. Whiteouts and
  opaque directories of upper layers are honoured. The result is a new blob `releases`: per
  image, the release tag, version, digest and read time per platform, whether the read was
  complete, and the name of its package list; each distinct package list is stored once in the
  blob, under the hash of its encoding, and named by every line that has it. The lines that ship
  fit 64 MiB unpacked, or less when the other blobs leave less of the 256 MiB an installation
  unpacks, in priority order (reviewed apps, then generated apps by weight), whole images only;
  what does not fit is left out, lowest priority first, and once the lines read fill the budget
  no further image is read. The blob is also capped at 32 MiB compressed, a backstop the budget
  keeps it well below, and `-force` does not lift that cap.
- **The builder's store stays publishable.** The store goes onto the branch `data`, where GitHub
  refuses a file over 100 MiB. A layer record keeps the members no reader reads by name only.
  After each build the store keeps the release reads that ship and the layer reads they name, at
  most 40 MiB of those. Over 80 MiB compressed the builder drops its layer reads, and it refuses
  a store still over that; the summary gives the store's size with every build.
- **Budgets.** The generator starts no project after 90 minutes into the build, the release
  reads no image after 150 minutes; the advisory collection gets the rest. The release reads
  stop at 600 manifest requests and 20 GiB of layer bytes (Docker Hub counts a manifest request
  as a pull). Without Docker Hub credentials the limit is 90 manifest requests, below the
  anonymous 100 in six hours; the optional secrets `VARDE_DOCKERHUB_USER` and
  `VARDE_DOCKERHUB_TOKEN` raise it. A source that refuses because of its rate limit is not
  asked again in that build. The registry work of one image stops after 30 minutes, and at the
  latest 20 minutes after the 150; a blob gets 2 minutes plus the time its size takes at 1 MiB/s,
  so a registry that trickles costs an image, not the build.
- **The installation compares, and makes no request.** For a container with findings in image
  packages and an entry with a release line, it matches the release's package list with the
  same distribution and ecosystem logic as its own image packages and says which findings the
  newest release fixes, which stay open (no release fixes them yet) and which it cannot tell.
  The platform compared is the container host's; when that is unknown only a single-platform
  image, which every host pulls alike, is compared. A claim is made
  only when the release is newer than the running version and of the same image variant; a
  package missing from the release counts as fixed only if the release was read completely.
  When the container runs the newest release it says so, and a release that fixes none of the
  findings is said to fix none of them yet.
- **Weekly check of the reviewed catalog.** `cmd/catalogcheck` runs C1, C3, C4 and C5 on
  `catalog/apps` every Monday. It corrects only what a check proves: the tag rule when a
  template reads the image's tags, and the note and `verified` date of an entry written without
  a look at the live sources. Corrections go into one pull request, `catalog: weekly check`, on
  a fixed branch; it is never merged automatically. A week with problems but nothing to correct
  appears only in the run's summary and artifact. A reviewed entry is never dropped from the
  package because of a failed check.
- **Backward compatible.** The `catalog` blob keeps at most 2000 entries and the `index` blob
  its three columns, so older installations load every new package unchanged and skip the blobs
  they do not know. Newer installations hold at most 20000 generated entries.
- **A guard against silent loss.** The builder refuses to sign when the generated entries or the
  release package lines fell by more than 30 % against the published package (the advisories,
  KEV entries and index rows keep their 10 %); `-force` releases that after a look at why.

## Alternatives
- A pull request with a YAML file per generated entry: hundreds of files to merge, and an entry
  is live only after someone does. Rejected.
- Generation without a visible result: nothing to audit. Rejected for the list on the branch.
- Reading the release's packages in the installation: outbound requests and load on the user's
  host, against ADR 0039. Rejected.
- Registry SBOM attestations as the source of release packages: few images carry them. May serve
  as a shortcut later.
- Free-form tag regular expressions from the generator: an unreviewed pattern in a signed
  package. Rejected for the template set.

## Consequences
- Recognition grows with the index without maintainer time, in the weaker `partial` form. A
  wrong generated entry is possible where all six checks pass; C4 and C6 narrow that, the weekly
  list makes it visible, and the entry never outranks a reviewed one.
- Every wrong or missing release claim is worse than none, so the display says "cannot tell"
  rather than guessing: an incomplete read, a different image variant or distribution, and a
  tag stream that went backwards produce no claim. Flavour-aware reads (the newest release per
  variant, for `-alpine` and similar images) are not built.
- The first builds are heavy: the layer reads of the first run are the largest the builder
  makes. Later runs mostly find layers in the store.
- The builder talks to more hosts than before: registries, GitHub releases, Docker Hub's
  repository metadata and NVD. Installations talk to the same single host as before.
- The package grows by the two blobs, within the 128 MiB blob and 256 MiB unpacked limits.
- The weekly pull request needs a token of the maintainer so that CI runs on it
  (`docs/data-package.md`); without it the job does nothing.
