# The data package

The project builds one signed data package a day. An installation that has a trust root reads its
advisories and its recognition table from it and asks nobody else about its apps. This document
is for the maintainer: what the package holds, how it is built and published, the keys behind it,
and what to do when something goes wrong. What an installation does with the package is in
[configuration.md](configuration.md#the-data-package); the checks it makes are in
[feed-trust.md](feed-trust.md). The decision is recorded in
[ADR 0039](adr/0039-daily-data-package.md); generated entries and release data are in
[ADR 0040](adr/0040-generated-catalog-and-release-fixes.md).

**State.** The trust root of the project is embedded (version 1, valid through 2028-11-12; see
[the key ceremony](#the-key-ceremony)). The daily workflow runs once the repository variable
`DATA_PACKAGE_ENABLED` is `true` and the feed key is stored as the secret `VARDE_FEED_KEY`. Until
the first package is published on the branch `data`, an installation built from this state finds
no package, says so under Settings › Data package and has no advisory data from it.

## What it holds

| Blob | Content |
|---|---|
| `catalog` | The reviewed catalog entries of `catalog/apps`. |
| `index` | The first-party index, `index/images.tsv` as `main` holds it (ADR 0038). |
| `advisories/shard-NN` | The published repository security advisories of every GitHub repository a catalog app or an index row names. One request per repository; the result is stored under the derived ID (`gh-<owner>-<repo>`) and under every catalog app that names the repository. |
| `generated` | Catalog entries the build generated for index images without a reviewed entry, after six machine checks. They rank below reviewed entries; at most 20000. |
| `releases` | The package lists of the newest release of every catalog app with a confirmed tag rule, per platform (linux/amd64 and linux/arm64). A package list shared by several lines (the two platforms of a release, releases on one base) is stored once. The lines fit 64 MiB unpacked, or less when the other blobs leave less of the 256 MiB an installation unpacks: reviewed apps first, then generated apps by weight; what does not fit is left out, lowest priority first. Capped at 32 MiB compressed, which the budget keeps it well below. |
| `enrichment/kev` | The CISA KEV list. |
| `enrichment/epss` | EPSS scores for the CVEs the package names, not the whole dataset. |

Not in it: distribution package data (2.6 GB at osv.dev), osv.dev package data, NVD,
endoflife.date. Those stay the switches they are in an installation.

The manifest names the channel `package`, carries the build time as sequence (Unix seconds) and
is valid for 7 days: six failed builds in a row pass before installations report stale data.

A change that renames or removes a blob older installations read needs a higher
`schema_version` in the manifest; they then say "too old for the current data package" and keep
what they have. Adding a blob needs nothing: older installations skip it.

## How it is built

`cmd/packagebuilder` does, in this order:

1. Checks the private feed key (`VARDE_FEED_KEY`) and that the trust root lists its public half.
   Nothing is requested before this passes.
2. Asks GitHub for the advisories of every repository, with conditional requests. Its store
   (`-db`) keeps the answers and the validators between builds, so a normal day costs mostly
   `304` answers. The store is used only when the feed key signed it (`builder.db.sig`);
   otherwise the builder starts cold and asks everything again. When the rate limit is reached it waits for the reset (`-max-wait`, 5 hours)
   instead of building from half the repositories. The workflow token allows 1,000 requests an
   hour per repository, so the first build of about 1,700 repositories takes two of those hours.
3. Before the advisories, generates catalog entries and reads release package lists (ADR 0040).
   The generator checks at most 150 new candidates per build and starts no project after
   `-generate-time` (90 minutes into the build); the release reads start no image after
   `-releases-until` (150 minutes) and stop at 600 manifest requests (`-max-manifests`) or 20 GiB
   of layer bytes. `-generate=false` and `-releases=false` leave either step out. The advisory
   collection gets the remaining time, and `-max-wait` is shortened by what these steps used.
   Optional secrets `VARDE_DOCKERHUB_USER` and `VARDE_DOCKERHUB_TOKEN` (a read-only Docker Hub
   access token) in the environment `data-package` authenticate to Docker Hub. Without them the
   release reads stop at 90 manifest requests, below the anonymous limit of 100 pulls in six
   hours per address, and what does not fit waits for the next build. `GITHUB_TOKEN` also serves
   the generator's GitHub requests. A registry that answers slowly costs one image, not the
   build: the registry work of an image stops after 30 minutes, and at the latest 20 minutes
   after `-releases-until`; a blob gets 2 minutes plus the time its size takes at 1 MiB/s. Once
   the lines read fill the budget of the `releases` blob, no further image is read.
4. Fetches the KEV list and the EPSS scores of the CVEs it now knows, with every build. If CISA
   or FIRST cannot be reached the build fails and yesterday's package stays.
5. Refuses to sign when more than 5 % of the repositories could not be read, or when advisories,
   KEV entries or index rows fell by more than 10 % against the package published before
   (`-previous`), or when the generated entries or the release package lines fell by more than
   30 %. It also refuses a `releases` blob above 32 MiB compressed. EPSS is not compared: scores
   come and go. `-force` lifts the shrink checks, not the cap on the `releases` blob. The counts
   of the published package are trusted only when the feed key signed them (`stats.json.sig`).
6. Refuses a trust root that is older than the published one, skips a version, changes a
   published version, or is a next version the published root does not endorse.
7. Signs the package, the counts and the store, then installs the package with the same client
   an installation uses. Only a package that passes is moved to `-out`.

The summary names every repository that could not be read, with the day it was last read: what
the package holds for it is that old. A repository that fails for long needs a look (renamed,
taken down, more advisories than the builder pages through). A repository of the index that no
longer exists answers "no advisories"; what it published before stays in the package, because
the images are still out there. A repository a catalog entry names has to exist: there a 404
counts as a failure.

The summary also says how many days the trust root has left, and shouts below 90.

A refused build exits non-zero and leaves nothing in `-out`; the workflow then publishes
nothing and yesterday's package stays.

By hand, for example to look at a build before trusting the workflow with it:

```sh
VARDE_FEED_KEY="$(cat /path/to/feed.key)" GITHUB_TOKEN="$(gh auth token)" \
  go run ./cmd/packagebuilder -db .cache/package/builder.db -out .cache/package/feed
```

## How it is published

`.github/workflows/data.yml` runs daily at 02:17 UTC and on demand. It fetches the branch `data`,
builds against it and replaces the branch with one commit:

```
feed/v1/root.json, root/<n>.json     the trust root chain
feed/v1/manifest.json, .sig          the signed manifest
feed/v1/blobs/sha256/<hash>          the blobs
feed/stats.json, .sig                counts of this package, the next build's baseline
cache/builder.db.gz, builder.db.sig  the builder's store for the next build, compressed
catalog/generated.json, generated.md the generated entries with their check results, and the
                                     changes against the previous build (new, changed, dropped)
```

The branch always has exactly one commit, so it does not grow. The workflow also keeps
`generated.json` and `generated.md` for 90 days as the artifact `generated-catalog` of the run,
the history beyond the branch's one commit, and puts the list (cut at a line, at a size GitHub's
step summary takes) into the job summary. Installations read
`https://raw.githubusercontent.com/bifrost0x/varde/data/feed`; they never read `cache/` or
`stats.json`.

**The branch is not trusted, by installations or by the builder.** More people and tokens can
write it than can sign a package: every collaborator with write access, every workflow with
`contents: write`. An installation verifies the manifest and every root step. The builder takes
back from the branch only plain files (the workflow refuses a tree with symlinks or anything
else), uses the store and the counts only with a valid signature of the feed key, and carries
only root files that parse and hold the version their name says. Someone who can write the
branch can therefore make a build fail or make it start cold, but cannot put anything into a
signed package.

**The store stays below GitHub's file limit.** GitHub refuses a file over 100 MiB on a branch,
and the store holds what the release reads read. After each build the builder keeps only the
release reads whose lines ship and the layer reads they name, at most 40 MiB of those (the oldest
go first), and gives the freed pages back. It then compresses the store as the workflow
publishes it: over 80 MiB it drops all layer reads (the next build reads those layers again),
and a store still over 80 MiB is refused like a broken build. `scripts/publish-data.sh` refuses
a `builder.db.gz` over 95 MiB. The summary of every build gives the size of `builder.db.gz` and
of the `releases` blob, compressed and unpacked.

### The weekly catalog check

`.github/workflows/catalog-check.yml` runs `cmd/catalogcheck` every Monday on the reviewed
entries in `catalog/apps`. It repeats checks C1, C3, C4 and C5 of ADR 0040 against the live
registries, GitHub and NVD and proposes only what a check proves: a corrected tag rule, or the
note and `verified` date of an entry once every check passed. Corrections go into one pull
request, `catalog: weekly check`, on the branch `catalog/weekly-check`, which is reset each week
and never merged automatically. Without corrections nothing is opened; problems appear in the run
summary and the artifact. An incomplete run (a source did not answer) leaves an open pull
request as it is.

The job that opens the pull request needs a token of the maintainer, so that CI runs on the
pull request. One time:

- Create a fine-grained personal access token of `bifrost0x`, for the repository
  `bifrost0x/varde` only, with the permissions Contents (read and write) and Pull requests (read
  and write), and a lifetime you will renew.
- In the repository settings, create the environment `catalog-check`, limit it to the branch
  `main` ("Deployment branches and tags": selected, `main`) and add the token as the secret
  `CATALOG_CHECK_TOKEN`. The limit is a repository setting the workflow cannot make.

While the secret is absent the job does nothing and says so in its log. The job that runs the
checks holds no secret.

The weekly index workflow is separate: it proposes a new `index/images.tsv` as a pull request.
The data package publishes whatever table `main` holds.

### When a build is refused

- **Too many repositories failed.** Usually GitHub had a bad hour. Run the workflow again. If it
  persists, read the job log: every failed repository is named with its error.
- **A count fell by more than 10 %.** Find out why before anything else: a broken upstream
  answer, a catalog or index change that removed many rows, or an attack on a source. If the drop
  is real and intended, run the workflow by hand with "force" ticked. Force does not release
  failed repositories.
- **The builder's store is too large without its layer reads.** The advisories or the release
  reads grew past what the branch can hold. Look at the sizes in the last summaries; the store
  can be dropped (delete `cache/` on the branch, or the branch itself) and the next build starts
  cold.
- **The package does not pass the client.** A bug in the builder or a key that the root does not
  list any more. Nothing was published; fix the cause.
- **The published package has no valid baseline.** `stats.json` on the branch is missing or was
  not signed by a current feed key. Expected once after a feed key rotation; otherwise someone
  changed the branch. Find out, then run with "force".
- **The branch holds entries that are not plain files**, or a file among the published roots is
  not a root. Someone changed the branch. Look at its history on GitHub (the reflog of force
  pushes is in the activity view), then delete the branch and run the workflow: it builds a
  fresh package from the sources. Installations that are more than one root version behind
  cannot follow the chain any more after that; they need the Varde release with the current
  root.

## The key ceremony

Two kinds of key. Both are Ed25519; `cmd/vardekeys` makes them and makes no network requests.

- **Root key.** Signs the trust root: the list of keys an installation accepts. It is used once
  now and once per rotation. It stays offline. Whoever holds it decides what every installation
  trusts.
- **Feed key.** Signs the daily package. It has to be where the build runs, so it lives as a
  GitHub Actions secret. If it leaks, the root key replaces it.

What this protects and what it does not: whoever controls the maintainer's GitHub account, or a
workflow on `main` that can read the secret, can sign a package. The root key bounds the damage
(a new root removes the feed key) but does not prevent it. Branch protection on `main`, the
secret scoped to an environment, the client's rollback and freeze protection and the builder's
shrink checks narrow it. The environment limit is a repository setting (step 6): the workflow
file cannot make it, and if it is skipped, or the key is stored as a repository secret instead,
any workflow on any branch can read the key. This is weaker than the three builders of ADR 0037, which stay the
target for the paid service.

### Before you start

- A machine that is offline while the root key exists on it in the clear: a laptop booted from a
  live system without network is enough. Build `vardekeys` beforehand (`go build ./cmd/vardekeys`)
  and carry the binary over, or have the Go toolchain and this repository on the machine.
- Two places for the root key that are not the machine you work on every day, for example two
  encrypted USB sticks kept apart. A hardware token cannot hold it: the tool reads a key file.
- The repository has to be public before the package is of use: `raw.githubusercontent.com`
  serves a private repository only with a token, which no installation has.

### Steps

1. **Make the keys** (offline machine):

   ```sh
   umask 077
   vardekeys keygen -out root.key
   vardekeys keygen -out feed.key
   ```

   Each call writes the private key (`*.key`, mode 0600) and its public half (`*.key.pub`). It
   never overwrites a file and never prints a private key. Nor does `vardekeys root` overwrite a
   root.

2. **Sign the trust root** (offline machine). Pick an expiry about two years ahead; an expired
   root stops every installation from updating until a rotation reaches it, so put the date in
   your calendar with months to spare.

   ```sh
   vardekeys root -version 1 -expires 2028-11-11 \
     -sign root.key -root-pub root.key.pub -feed-pub feed.key.pub \
     -out production.json
   vardekeys check -root production.json -feed-pub feed.key.pub
   ```

3. **Store the root key.** Copy `root.key` to the two offline places, then delete it from the
   machine. From here on it is only needed for a rotation.

4. **Carry three files to your normal machine:** `production.json`, `feed.key`, `feed.key.pub`.
   `production.json` and the `.pub` files are public. `feed.key` is the only secret that leaves
   the offline machine.

5. **Embed the root.** Put `production.json` at `internal/feed/roots/production.json` and open a
   pull request. `go test ./internal/feed` verifies that it is a production root that holds by
   itself. From the release that contains it, installations have a trust root.

6. **Give the workflow the feed key.** In the repository settings:
   - Environments: create `data-package` and limit it to the branch `main` ("Deployment branches
     and tags": selected, `main`). This limit is what keeps the key from other branches; do not
     skip it.
   - In that environment, add the secret `VARDE_FEED_KEY` with the content of `feed.key`
     (the whole PEM file, including the BEGIN and END lines). Then delete `feed.key` from your
     machine; keep a copy only if you want to build by hand.
   - Variables: add the repository variable `DATA_PACKAGE_ENABLED` with the value `true`.
   - Branches: protect `main` (pull requests, required checks) if it is not yet. Do not protect
     `data`: the workflow replaces it with a force push.

7. **Run the first build.** Actions, workflow "data", "Run workflow". Expect about two hours
   because of the rate limit. Afterwards the branch `data` exists with one commit, and the job
   summary shows the counts. Later builds take minutes.

8. **Check from an installation** that has the root (a build of `main` after step 5):
   Settings, Data package, "Update now". It shows the sequence and the build time.

To switch everything off again: set `DATA_PACKAGE_ENABLED` to anything but `true`. Installations
keep the last package and report it as stale after `VARDE_FEED_STALE_AFTER`.

### Replacing the feed key

When the feed key may have leaked, or as routine once a year:

```sh
# offline machine, with root.key and the current root (here production-1.json) at hand
vardekeys keygen -out feed2.key
vardekeys root -version 2 -expires 2029-11-11 -previous production-1.json \
  -sign root.key -root-pub root.key.pub -feed-pub feed2.key.pub \
  -out production-2.json
vardekeys check -root production-2.json -previous production-1.json -feed-pub feed2.key.pub
```

The version is the last one plus one, and the root is signed by a root key the last root
trusts. This also works after the last root has expired: installations accept the successor of
an expired root, so a rotation is how updates come back after a missed date. `-previous` makes
the tool check exactly that: it refuses to write a root that
installations trusting the last one would not accept, because such a root, once published,
strands every installation and cannot be repaired by a later version. Then: put
`production-2.json` at `internal/feed/roots/production.json` in a pull request, replace the
secret `VARDE_FEED_KEY` with `feed2.key`, and run the workflow by hand with "force" ticked (the
baseline and the store of the last build were signed by the old feed key and no longer verify;
the builder starts cold that once). The builder publishes the new root
beside the package and carries the earlier versions along (`feed/v1/root/<n>.json`); an
installation fetches the root before the manifest, follows the chain version by version and stops
accepting the old feed key with its next check. Raise the version by exactly one per rotation:
the builder refuses a root that is older than the published one, skips a version, or changes a
published version. Installations that
were built with root 1 need no update for this.

Replacing the root key works the same way with a second `-sign` and the new `-root-pub`: the
new root has to be signed by a key of the last root and by the new key.

```sh
vardekeys keygen -out root2.key
vardekeys root -version 3 -expires 2030-11-11 -previous production-2.json \
  -sign root.key -sign root2.key -root-pub root2.key.pub -feed-pub feed2.key.pub \
  -out production-3.json
```

### If the root key is lost or leaked

There is no clean way back from either, which is why there are two copies and why the key never
touches a networked machine.

- **Lost** (both copies): the current root keeps working until it expires, and the feed key keeps
  signing. No rotation is possible any more, so the feed key cannot be replaced and the expiry
  cannot be moved. A new root 1 with new keys is a new chain: an installation keeps the root it
  already trusts in `<data>/feed/root.json` and does not take a different one from a Varde
  update, and the builder refuses to publish a root that does not continue the published chain.
  Starting over therefore needs all of: new keys and a new root embedded in a release, the branch
  `data` deleted and rebuilt, and on every installation the update plus the removal of
  `<data>/feed` (Varde then starts from the embedded root). Until a user does that, their
  installation reports stale data. Making the client prefer a newer embedded root would remove
  the manual step; it is not built, because it must not become a way around the chain.
- **Leaked:** whoever has the key can sign a next root that installations follow, if they can
  also get it onto a mirror the installations read. Publish a rotation that replaces the root key
  at once (signed by the leaked key and the new one, as above); installations that fetch it
  before the attacker's root are safe again. There is no revocation beyond that.
