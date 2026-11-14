# 0042 Second advisory sources in the data package

Status: Accepted (the builder's collection, the origin mark, the ranking and the display are
built; the package carries the records from the next build)

## Context
The data package held what projects publish as GitHub repository advisories, and nothing else.
A project that publishes its flaws elsewhere (nginx, a CVE list on its site) had no findings in
the default setup, whatever version ran, and a project whose advisories lack a fixed version
kept findings without one. osv.dev and the NVD were available only as direct queries from the
installation, off by default, because they tell a third party what runs (ADR 0017). Most
installations therefore never had the data, although asking about a catalog app reveals nothing
when the builder asks: it asks about the whole catalog.

## Decision
- **The builder asks the second sources.** After the repositories, `cmd/packagebuilder` asks
  osv.dev about the `osv_packages` of every catalog app, and the NVD about the CPEs of every
  catalog app whose coverage is `partial` or `limited`, with the sources of direct mode. Reviewed
  and generated entries count alike; a generated entry has a CPE only when check C5 tied it to
  the repository (ADR 0040).
- **The NVD only where the project's own data is incomplete.** For an app with `coverage: full`
  the CVE records are derived from the advisories the package already carries and add coarser
  ranges, not knowledge. The NVD is asked about every app with a CPE; for an app with full
  coverage only the records ship that belong to a flaw whose project advisory names no end of
  the affected versions (no fixed version, no last affected one, no list of versions).
- **An open range gets its end from the second record.** A project advisory that only says from
  which version a flaw exists ("from 2.8 on", the fixes named in its text) kept every later
  version affected and never named an update. When the deciding record of a flaw is such a
  range and another record of the same flaw names fixed versions, the finding stays the
  project's and takes its end from the other: the fixed version when the other record says
  affected, and no finding when the running version is at or above a fix on its own minor line
  or above every fix the other record names. A version in a gap of the other record's ranges
  (a line it does not list) stays affected, with the next fix above it as the update: the
  second record is trusted for what it states, not for what it leaves out. The finding names
  the record that completed it.
- **Under the catalog app, once.** A record ships under the app whose entry names the package or
  the CPE. A record the repository already published under that app is not repeated; among the
  second sources osv.dev comes first. A record stored for a CPE or package the entry no longer
  names is not shipped.
- **Every such record names its origin.** `database_specific.varde_origin` is `osv` or `nvd:`
  and the CPE. An installation ranks it by that origin, below what the project published
  (project, then osv.dev, then the NVD), so within one CVE the project's range decides; shows
  the origin with the finding's source; and leaves out NVD records of a CPE the app as read for
  an image does not carry. The key sits in a field older installations already accept and
  ignore.
- **Never fatal.** A second source that fails or runs into its rate limit does not stop the
  build: the package carries what earlier builds stored, and the summary names the source that
  stopped early. The builder reads an NVD API key from `VARDE_NVD_API_KEY`, which raises the NVD's limit; the
  data workflow does not pass one, and its set of secrets is guarded by a test.
- **Installations ask no one.** The direct queries stay what they were: off, and for apps the
  package does not cover.

## Alternatives
- The NVD for every app with a CPE: more records for the same flaws, with ranges from CPE
  configurations that are coarser than the project's. Rejected while nothing measures the gain.
- A source field on the advisory line: older installations decode lines strictly and would
  refuse the package. Rejected for the key inside `database_specific`.
- Leaving the choice to the installation: the data would stay off for most. Rejected.

## Consequences
- Apps with limited advisory data get findings in the default setup. Their ranges come from the
  NVD and are as precise as the NVD's CPE configurations.
- The first build with the sources adds requests: one per app to osv.dev plus one per changed
  record, and one per CPE to the NVD at its published pace (seven seconds apart without a key).
- A project advisory with an end of its own is never overruled by a second record.
