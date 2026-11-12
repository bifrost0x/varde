# 0039 One signed data package a day, the same knowledge for everyone

Status: Accepted (the installation, the builder, the workflow and the key tool are built; the
package is switched on by the key ceremony in `docs/data-package.md`)

## Context
A free installation asked GitHub about every app it recognised, every six hours (ADR 0003). That
tells GitHub which apps run where, and it puts a tool into homelabs that queries dozens or
hundreds of repositories. ADR 0038 added the first-party index, which made the number of
recognised apps, and with it the number of queries, much larger. The maintainer's requirements:
an installation fetches as little as possible, nothing per app, and what it knows must not depend
on paying. The uplink service of ADR 0037 does not exist yet and must not be a precondition.

## Decision
- **One package, built centrally, once a day.** A GitHub workflow collects the published
  security advisories of every repository the catalog and the index name, the KEV list and EPSS
  scores for those advisories, and publishes them with the catalog and the index as one signed
  package. Details: `docs/data-package.md`.
- **In the main repository, on the branch `data`.** No second repository. The branch is replaced
  by one commit per build, so it does not grow and triggers no CI.
- **The same trust path as the feed** (ADR 0005): signed manifest, content-addressed blobs,
  rollback and freeze protection. The package is a second channel of the feed client beside the
  uplink, with its own mirrors and its own rollback floor; the signed manifest names its channel.
- **The same knowledge free and paid.** Recognition and advisories are identical. A subscription
  (ADR 0037) differs by how often the data is refreshed and by further benefits, never by what
  Varde recognises or reports.
- **Direct queries become opt-in.** With the package in use Varde asks GitHub only about apps the
  package does not cover, and only when the user switches that on. Such apps are shown as having
  no advisory source, not as clean. A package that cannot be fetched keeps the last one in use;
  Varde never starts asking single sources by itself.
- **Forward compatible.** An installation skips blobs it does not know, so the package can grow.
  An incompatible change raises the schema version; older installations then say they are too
  old and keep what they have. "Update now" therefore works whatever version is installed.
- **One feed key in CI, the root key offline.** The feed key is a GitHub Actions secret with a
  threshold of one; the root lists it and can replace it. Stated plainly: control of the
  maintainer's GitHub account, or of a workflow on `main` that reads the secret, is enough to
  sign a package.

## Alternatives
- Ship the data only with Varde releases: no outbound request at all, but advisories would be as
  old as the installed release. Rejected for the advisories, kept for the index as a fallback.
- A subfolder on `main` with a daily commit: megabytes of history per day, and a CI run per data
  commit.
- A release asset under a fixed tag: two hosts because of the redirect, and a URL layout that
  does not match the feed.
- `actions/cache` for the builder's store: one more action to trust and pin. The store lies on
  the `data` branch instead. That branch is writable by more than can sign a package, and a
  store someone else wrote would be signed into the next package; so the builder signs the store
  and the counts with the feed key and uses them only when the signature holds, and takes
  nothing else from the branch but plain, parsed root files.
- Wait for the three builders of ADR 0037: they need the service. The package must work without.

## Consequences
- A default installation, once a release embeds the trust root, talks to one host
  (`raw.githubusercontent.com`) about once a day. GitHub sees an IP address and that it fetches
  the Varde package, not which apps run there.
- The package carries GitHub repository advisories only. Distribution packages, osv.dev package
  data, NVD and endoflife.date stay switches of the installation and count beside the package.
- The repository has to be public for the default mirror to work.
- A compromised feed key can publish false advisories or withhold real ones until the root
  replaces it. The builder's shrink checks and the client's rollback protection limit silent
  removal; they do not stop a forged addition. The three builders of ADR 0037 remain the answer
  to that, for the paid service first.
- An expired root stops updates for every installation. Rotations and their dates are the
  maintainer's duty (`docs/data-package.md`).
- The first build takes about two hours because of GitHub's rate limit for workflow tokens
  (1,000 requests an hour per repository); later builds are mostly conditional requests.

## Amendment (2026-11-12): two more blobs
The package also carries generated catalog entries and the package lists of the newest releases
(blobs `generated` and `releases`), and the builder refuses a build in which either fell by more
than 30 % (ADR 0040). Older installations skip both blobs.
