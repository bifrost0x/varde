# 0023 Evidence, trust, stable assets and measured recognition

Status: Accepted

## Context
Alerts are only worth something when the inventory is right: which software, which version, on
which machine. Until now a version was the first value of an extraction chain, a machine's ID
changed with its best source, and nothing measured how often Varde is right. Floating tags, labels
that name a branch, unauthenticated version endpoints and the same machine seen by several
sources are the usual ways recognition goes wrong.

## Decision
- **Every version carries evidence.** An identification lists every observation of the version
  (method, raw value, canonical value, which one was used), not only the one it took.
- **Trust is earned, not assumed.**
  - `confirmed`: an authoritative source states the version (the publisher's image label or version
    tag, an upstream package, a manual entry, the user's `varde.version` label) and no other source
    contradicts it. A shorter form agrees with a longer one (tag `1.37` and label `1.37.5`).
  - `reported`: only a source that cannot be verified states it (an app's unauthenticated version
    endpoint, a version a service reports).
  - `conflict`: sources disagree. Varde shows both and does not pick one; `varde.version` settles it.

  Only confirmed versions produce `affected` findings and notifications. A reported or disputed
  version in an affected range yields `unverified` with the reason. This tightens ADR 0022, under
  which a validated endpoint counted as exact.
- **PURL as the component identifier.** Identifications carry a package URL: images as
  `pkg:docker/<namespace>/<name>@<digest or tag>`, native packages as
  `pkg:deb|rpm|apk/<distro>/<name>@<version>?distro=<id>-<version>`. The catalog ID stays the
  product identifier, CPEs map to NVD.
- **Stable assets.** Machines are still merged from evidence at read time (ADR 0021), now also by
  MAC address (Proxmox guest configuration, `/sys/class/net` over SSH) and `/etc/machine-id`, which
  tie records together across networks. Every minute the identity keys of each machine
  (`host:<record>`, `mac:<mac>`, `mid:<machine-id>`) are stored with a stable asset ID; a machine
  whose keys belong to several assets keeps the oldest, a machine without known keys gets a new
  one. Keys not seen for 90 days expire. The ID survives a reinstalled integration, changed
  addresses and a better source appearing.
- **Recognition is measured.** `internal/eval` runs the production code against a corpus with
  ground truth: real image digests and labels read from the registries, real package lists,
  topology and matching cases. It reports app precision and recall, version accuracy, version
  coverage (versions found among all app cases, also those where nothing states the version),
  duplicated and falsely merged machines, and advisory precision and recall. A gate file holds the
  measured baseline; a change that lowers a value fails CI. A self-test injects wrong truths and
  fails if the harness does not see them. Every catalog app needs a corpus case.

## Alternatives
- One confidence enum for app and version together: hides why a version is doubtful and cannot
  express disagreement.
- Ground truth from Varde's own output: measures nothing. The corpus states its basis per case
  (pinned tag, publisher label, independently found release, unknown); unknown truths count as
  errors when Varde reports a version anyway.
- Live registry pulls in CI: rate limits and changing tags make numbers irreproducible. The corpus
  is recorded; refreshing it is a separate, reviewed change.

## Consequences
Some findings that were `affected` become `unverified` when the version is only reported or
disputed; they stay visible and never notify. The first measurement shows full precision and a
version coverage of 75 %: a quarter of the apps run floating tags without a version label, which
the registry digest resolution of the next stage addresses. Asset IDs of the API (`view=merged`)
change once from the source record ID to an `a-…` ID after the first refresh.
