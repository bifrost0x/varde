# 0037 The central feed service and the paid data subscription

Status: Proposed

## Context
Varde is complete without a central service: every installation reads the daily data package
(ADR 0039) or, in direct mode, asks osv.dev, GitHub, NVD and the distributions itself (ADR 0003).
The project offers a paid subscription, the "uplink": the same knowledge as the free package,
refreshed more often and built with stronger guarantees, plus data too large for the package
(distribution packages), no rate limits and air-gapped use. What Varde recognises and which
advisories it knows never depends on the subscription (ADR 0039). The client already
verifies signed feeds (ADR 0005, `docs/feed-trust.md`); the server side does not exist.

The osv.dev exports of the ecosystems Varde checks are 2.6 GB as zip (measured 2026-11-11). One
feed every installation downloads whole cannot carry that, and the client limits a feed to 256 MB
and a metadata file to 1 MiB. Live sources (osv.dev exports, KEV, EPSS, CSAF) cannot be pinned to
a point in time, so independent builders fetching them see different data. When this was
proposed the root format of ADR 0005 rejected unknown key roles, and no production root had been
embedded. Both changed with the uplink switch and the data package: the client ignores keys of
unknown roles (ADR 0038), and the first production root is made for the data package in the
current format (ADR 0039).

## Decision
The architecture is described in `docs/feed-architecture.md`. In short:

- **Static, signed data behind a thin gate.** Builders publish files to an origin store; a gate
  checks licenses and serves the files. No accounts, no database outside the license service.
- **Shards per ecosystem release, 256 buckets each, two-level manifest.** An installation
  downloads every bucket of the ecosystems it uses: the service learns ecosystems, never packages.
  The signed manifest names one content-addressed index per ecosystem release; the index lists the
  buckets. Package names are normalised per ecosystem by a fixed rule.
- **Three builders at three providers, threshold 2.** The leader of the hour stores a
  content-addressed input snapshot; the other builders fetch the same sources themselves,
  cross-check the snapshot record by record within a consistency window, rebuild from it
  deterministically and sign. Byte equality covers the build, the cross-check covers the inputs.
  One builder or provider can fail without stopping the feed.
- **Roles in the root.** Roles `root`, `feed`, `license` and `override` with a threshold each;
  keys with an unknown role are ignored and never counted, unknown fields stay an error, and
  incompatible changes raise `spec_version`. The roles `root`, `feed` and `license` are built in
  the current format, which the first production root uses (ADR 0039); the service adds the
  `override` role and the feed threshold of 2 with a rotation, not with a new root 1.
- **Checks beyond signatures.** Builders refuse to sign a build that shrinks beyond thresholds; a
  canary checks every published feed with the real client; Varde refuses a manifest whose records
  for its ecosystems drop by more than 20 % against a 30-day baseline. Legitimate drops are
  released by acknowledgements signed with a separate override key, neither a feed key nor a root
  key.
- **Offline-verifiable licenses without a customer reference.** Ed25519-signed license documents
  with an expiry and a grace period, signed by keys of role `license` in the root; the gate holds
  only public keys and a signed revocation list; renewals are fetched automatically. Expiry falls
  back to the free data package (ADR 0039), or to direct mode in an installation without it.
  The gate serves the root files without a license, so an installation can follow a license key
  rotation before its license is verified and sent.
- **Sales through Paddle** as merchant of record, with a webhook to a small license service;
  refunds revoke at once. Lemon Squeezy is rejected because it is moving its merchants to Stripe
  Managed Payments.
- **Price.** EUR 3.49 a month, billed yearly (EUR 41.88), optionally EUR 3.99 monthly: the fixed
  fee per transaction makes monthly billing expensive, and the price has to pay for the service
  and for curation, not only for infrastructure. The price was set when curated data was meant
  to be exclusive; it is reviewed before production against what the subscription now offers.
- **No feature gating and no exclusive knowledge.** Everything in Varde works without the
  subscription, and the free data package carries the same recognition table and the same
  advisories (ADR 0039). The subscription sells freshness (hourly instead of daily), the stronger
  build (three builders instead of one feed key), the data that does not fit the free package,
  and support of the project. Vendor advisories the project curates go into the free package as
  well; the subscription gets them sooner, not exclusively.

## Alternatives
- Two builders, threshold 2: no redundancy; one builder offline for longer than the manifest
  lifetime makes every subscriber stale.
- Independent fetches and byte equality without an input snapshot: fails whenever a record
  changes between the builders' fetches, which is the normal case.
- One manifest listing every bucket: 2 to 3 MB every hour, above the client's metadata limit.
- Root keys releasing legitimate drops: exposes the offline keys to routine operation.
- Unlinkable access tokens (blind signatures): would separate payment from fetching, at the cost of
  a protocol of its own; deferred.
- Lemon Squeezy: see above.

## Consequences
- Feed format 2 (indexes, acknowledgements, ecosystem selection, plausibility baseline) is needed
  in the client before the service starts. It arrives as a higher `schema_version`; installations
  that are older say so and keep the data package.
- The project is run by one person. The thresholds protect against the loss of one token and the
  compromise of one builder or provider, not against the operator or the operator's workstation;
  the architecture document states this and the controls that narrow it.
- The service can technically link a customer to the ecosystems they use; not doing so is an
  organisational commitment stated in the privacy notice.
- Running cost of about EUR 30 a month: break-even at about 12 yearly subscribers, without the
  operator's time. Curation of vendor advisories is the main human effort and is measured in
  phase 1 before the price is fixed.
- Every data source is licence-checked before inclusion; ShareAlike or non-redistributable
  sources stay out.
- Whether the subscription makes Varde a commercial product under the Cyber Resilience Act is
  assessed before production; the outcome may raise Varde's vulnerability and release process to
  manufacturer level.
- The build plan has five phases (measurement first); each is one pull request.
