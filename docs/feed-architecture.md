# Feed service architecture

> The free daily data package (ADR 0039, [data-package.md](data-package.md)) carries the same
> recognition table and the same advisories as the uplink. Where this document says the
> subscription differs by data or curation, ADR 0039 overrides it: the subscription differs by
> freshness, by the stronger build and by data too large for the package.

The design of the paid data subscription ("uplink"): a central service that builds, signs and
serves curated vulnerability data to Varde installations. Status: proposed (ADR 0037); nothing of
the server side exists yet. The client side that verifies a signed feed is in `internal/feed` and
described in `docs/feed-trust.md`.

## 1. Goals and non-goals

Goals, in this order:

1. **Integrity beyond doubt.** No single machine, key or provider can make installations accept
   wrong, incomplete, old or frozen data without it being detected. The service is run by one
   person; section 6.1 states plainly what that person can and cannot do alone.
2. **Privacy.** The service learns as little as possible about what runs where: no package lists,
   no host names, no telemetry. What the operator could still link is stated in 6.5, not hidden.
3. **Availability without dependence.** Installations keep working when the service is down, the
   subscription ends or the network is cut: direct mode stays complete and free (ADR 0003), the last
   verified feed stays installed. One builder or one provider failing does not stop the feed.
4. **Minimal operation.** One person, a few hours a month for operation, no on-call duty.
   Everything that can be automated is; nothing needs a human except key ceremonies, drop
   acknowledgements, curated advisories and abuse decisions. Curation is the real cost and is
   measured, not assumed (phase 1).
5. **Price.** The subscription must cover infrastructure and fees from about a dozen yearly
   subscribers on.

Non-goals: accounts, a web portal, per-user dashboards, usage analytics, feature gating in Varde,
exclusivity of the data (6.6).

## 2. What the subscription is

| | Direct mode (free) | Uplink (paid) |
|---|---|---|
| Sources | osv.dev, GitHub, distributions, NVD (with key), KEV, EPSS, endoflife.date, queried by each installation | Everything in direct mode, from full exports, plus vendor CSAF feeds, hand-curated vendor advisories (Proxmox, Synology, QNAP, Ubiquiti, AVM, Home Assistant), exploit signals (Exploit-DB IDs, Metasploit modules, Nuclei templates) |
| What third parties see | Each source sees the installation's packages or products | No upstream source sees the installation. The service sees the ecosystem releases in use and, through the license, which customer uses them (6.5) |
| Rate limits | The installation's own (NVD without key: 5 requests / 30 s) | None for the installation |
| Air-gapped use | No | Yes (export the feed to a directory) |
| Freshness | Each source on its own schedule | One consistent snapshot every hour |
| Checking | Varde's matcher | The same matcher; curated data adds firmware and appliance advisories |

Varde has no feature that needs the subscription. The difference is data, curation and where the
data comes from. Most of the data is openly licensed and can be passed on by any subscriber; the
subscription sells convenience, privacy towards upstream sources and curation, not exclusive
access (6.6).

## 3. Components

```
              upstream sources (osv.dev exports, NVD, GitHub, CSAF, vendors, KEV, EPSS)
                  |                       |                       |
        +---------v-------+     +---------v-------+     +---------v-------+
        | builder A       |     | builder B       |     | builder C       |  three providers,
        | (provider 1)    |     | (provider 2)    |     | (provider 3)    |  no inbound ports
        +--------+--------+     +--------+--------+     +--------+--------+
                 |  leader of the hour fetches the input snapshot;             |
                 |  the others fetch independently, cross-check it,            |
                 |  rebuild from it and sign (4.1); threshold 2 of 3           |
                 v                       v                       v
        +--------------------- staging (read-write for builders) ---------------------+
        +--------------------- origin store (versioned, published files) -------------+
                                               |
                                      +--------v--------+        +------------------+
                                      |  gate           |<-------| license service  |
                                      |  (license check,|  signed| (MoR webhook,    |
                                      |   static files) |  revocation list  issues licenses) |
                                      +--------+--------+        +------------------+
                                               | TLS
                                       Varde installations
```

| Component | What it does | What it holds | Exposure |
|---|---|---|---|
| Builder A, B, C | Fetch sources, cross-check the input snapshot, build the feed, sign the manifest | One feed key each (online), source credentials (NVD key, GitHub token) | Outbound only; SSH over WireGuard |
| Staging | Input snapshots, candidate builds and their signatures while a build is being agreed | Public data and signatures only | Read and written by the builders, each with its own credential; not reachable by the gate |
| Origin store | Keeps published manifests, indexes and blobs with history | Public data only | Written by the builders (append-only credentials); read by the gate |
| Gate | Checks the license of each request, serves files | The trusted root (for the license keys), revocation list | Public HTTPS |
| License service | Receives MoR webhooks, issues and renews licenses, publishes the revocation list | License *signing* key, a SQLite file of orders | Public HTTPS for the webhook and the one-time download link only |
| Canary | Fetches and verifies every published feed with the real Varde client | Nothing secret | Outbound only; shares no credentials with the builders or the gate |

Each is one Go binary under systemd, with no container runtime, no database server and no message
queue. The gate and the license service can share a VM (6.5 states what that means for privacy);
the builders share nothing, not even a provider.

Three builders with a threshold of two keep the feed going when one builder or one provider is
down, which two builders with a threshold of two would not: a builder offline for longer than the
manifest lifetime (72 h) would have made every subscriber stale.

## 4. Data model and distribution

### 4.1 What is built, and how builders agree on it

Live sources cannot be pinned to a point in time. The osv.dev exports contain only the current
version of each record; KEV, EPSS and the CSAF feeds have no history either. Two builders fetching
independently will regularly see different data, because records change between their fetches, so
"same inputs, same bytes" cannot rest on independent fetches. Inputs and build are therefore
separated:

1. **Leader.** The leader of an hour is the builder `sequence mod 3`; a leader that does not
   produce a snapshot in time is skipped and the next builder leads.
2. **Input snapshot.** The leader downloads every source (osv.dev per-ecosystem `all.zip`, NVD
   JSON 2.0 incremental, GitHub Advisory Database git mirror at a commit, CSAF provider metadata,
   KEV, EPSS, endoflife.date, the curated repository at a commit) and stores the raw bytes
   content-addressed in staging, with an input manifest: per source the URL, fetch time, SHA-256
   and, for git, the commit.
3. **Cross-check.** Every other builder fetches the same sources itself and compares them with the
   leader's snapshot record by record. The snapshot is consistent when every record in it is equal
   to the builder's own or older than it by `modified`, and no record the builder has with a
   `modified` older than the consistency window (initially two hours, sized in phase 1) is missing
   from it. Git sources must match the commit exactly or be an ancestor of the builder's own head
   within the window. A builder that finds the snapshot inconsistent does not sign and alerts.
4. **Build.** Every builder, the leader included, builds deterministically from the leader's
   snapshot: normalise every record into the compact form the matcher uses (ID, aliases, modified
   time, severity and CVSS, summary, references, and per affected package only the ranges and
   versions of that ecosystem; details texts cut to the first paragraph), file each record under
   every (ecosystem release, normalised package name) it names, write the buckets, indexes, the
   catalog, KEV, EPSS and end-of-life blobs, and the manifest.
5. **Sign and publish.** Each builder that passed 3 and produced the same manifest bytes as the
   leader puts its signature in staging. The first builder that sees two valid signatures on the
   same bytes copies the files to the origin store.

The build is deterministic: sorted inputs, fixed timestamps (the newest `modified` of the
inputs), zstd with a fixed level and no dictionary. Byte equality covers the build (tooling,
binaries, normalisation); the cross-check covers the inputs. A compromised leader can at most hold
back an update of a record for the consistency window; it cannot add, alter or drop records
unnoticed, because the other builders fetch the same sources themselves.

Measured on 2026-11-11, the osv.dev exports are 2.6 GB as zip (Chainguard 1115 MB, Ubuntu 774 MB,
Wolfi 295 MB, npm 210 MB, Debian 77 MB, the rest under 150 MB together). Compaction per release
removes most of it: a record of Ubuntu lists every release, a shard of Ubuntu 24.04 keeps only
that release's ranges. Chainguard and Wolfi have no releases, so compaction does little for them;
whether they stay below the client's size limit on their own is a measurement target of phase 1.

### 4.2 Shards: privacy by ecosystem, efficiency by bucket

A shard is the data of one **ecosystem release** ("Debian:12", "Ubuntu:24.04:LTS", "PyPI",
"Go"), split into 256 buckets by the first byte of SHA-256 of the **normalised** package name.
Normalisation is part of the format and fixed per ecosystem: PEP 503 for PyPI, lower case for npm,
the module path as is for Go (case-sensitive), the **source** package for Debian and Ubuntu (OSV
names source packages; the client maps binary to source packages before the lookup), and so on for
each ecosystem in the format specification.

An installation downloads **all** buckets of every ecosystem release it has, not only those of
its packages. The gate therefore learns which distributions and language ecosystems an
installation uses, never which packages. Buckets exist only so that an update downloads the few
that changed: a new Debian advisory touches one bucket of Debian:12, about 1/256 of it.

Rejected alternative: downloading only the buckets of one's own packages (k-anonymity by bucket).
The set of bucket numbers an installation requests is stable over time and identifies the
installation and, with public package lists, narrows what it runs. Ecosystem-level fetching costs
bandwidth, not privacy; bandwidth is cheap.

### 4.3 Manifest format 2: a small manifest and one index per ecosystem release

A single manifest listing every bucket would not work: 256 entries of about 105 bytes per
ecosystem release are 27 KB, and with 80 to 120 ecosystem releases the manifest would be 2 to
3 MB, above the client's metadata limit (`maxMetadataBytes`, 1 MiB) and changing every hour for
every installation. Format 2 therefore has two levels, like TUF's snapshot:

The **manifest** (signed by the feed threshold) names one index per ecosystem release:

```json
{
  "signed": {
    "format": 2,
    "sequence": 18342,
    "created_at": "2026-11-11T08:00:00Z",
    "expires_at": "2026-11-14T08:00:00Z",
    "inputs_until": "2026-11-11T08:00:00Z",
    "inputs": {"sha256": "...", "size": 2345},
    "blobs": { "catalog": {...}, "kev": {...}, "epss": {...}, "eol": {...} },
    "ecosystems": {
      "Debian:12": { "records": 41234, "index": {"sha256": "...", "size": 27123} },
      "PyPI":      { ... }
    },
    "acknowledgements": [ {"sha256": "...", "size": 812} ],
    "attribution": [ {"source": "osv.dev", "license": "CC-BY-4.0", "url": "..."}, ... ],
    "counts": { "records": 812345, "by_source": { "osv": 700000, "nvd": 90000, "csaf": 20000, "curated": 345 } }
  },
  "signatures": [ {"keyid": "...", "sig": "..."}, {"keyid": "...", "sig": "..."} ]
}
```

An **index** is a content-addressed blob per ecosystem release listing its 256 buckets (SHA-256,
size, uncompressed size). Because the manifest carries the index hash, the index needs no
signature of its own. `inputs` points to the input manifest of 4.1, so anyone can audit which
upstream bytes a feed was built from. `acknowledgements` are explained in 6.3.

With about 150 bytes per ecosystem release, the manifest stays around 20 KB. The existing checks
of `docs/feed-trust.md` apply unchanged: signatures against the feed keys of the trusted root,
expiry, no future `created_at`, no lower `sequence`, same sequence only with the same bytes, size
limits before and during decompression. New: the unpacked-size limit applies per installation to
the sum of its ecosystems, not to the whole feed; the `counts` are checked against a baseline
(6.3).

### 4.4 Root format 2

The root of `docs/feed-trust.md` knows two key roles, `root` and `feed`, and rejects unknown roles
and unknown fields (`ParseRoot` and `decodeStrict` in `internal/feed/meta.go`). That strictness is
right, but it means a root version with a new role would be rejected by every client released
before it, and the chain walk of those clients would stop there for good. Since no production
root has been embedded yet, the root format can still change at no cost; it must be final before
root 1 is created (phase 5):

- **Roles** `root`, `feed`, `license` (signs license documents and revocation lists, 5.1) and
  `override` (signs acknowledgements, 6.3), with a threshold each. A license key is never counted
  for a manifest, a feed key never for a license, and so on.
- **Evolution rule.** Keys with a role the client does not know are ignored: they are not counted
  for any threshold and do not make the root invalid. Unknown fields anywhere else stay an error.
  A future role can thus be added without stranding old clients, and an old client can never be
  made to count a key it does not understand.
- **Spec version.** A change that old clients must not ignore raises `spec_version`; old clients
  then stop at that root and show a notice asking for an update, rather than accepting data they
  cannot check.

### 4.5 Client flow

1. Read the license file (`VARDE_FEED_LICENSE_FILE`), verify its signature against the license keys
   of the trusted root and its expiry offline. No license or an expired one: direct mode, with a
   notice "uplink expired since ...".
2. Walk the root chain, fetch the manifest (conditional GET), verify it.
3. Work out the ecosystem releases in use from the inventory; fetch their indexes and the buckets
   whose hash is not cached; verify length and hash; check the counts (6.3); install in one
   transaction.
4. Keep the previous manifest, indexes and buckets until the new set is installed; a failure
   leaves the previous verified state active.
5. Ecosystems that appear later (a new image on Alpine) are fetched on the next run.

Traffic per installation: the first fetch is the full size of its ecosystems. After that, per
hour, the manifest (about 20 KB), the indexes of the ecosystems that changed (about 27 KB each)
and the changed buckets. For an installation with five ecosystem releases this is estimated at a
few MB a day; 1000 installations would then use a few hundred GB a month, inside what small VMs
include. Phase 1 replaces the estimate with measured change rates.

## 5. Licenses and sales

### 5.1 License document

```json
{
  "signed": {
    "license": "lic_7Qm2...",          // random, 128 bits
    "plan": "uplink",
    "not_before": "2026-11-11T00:00:00Z",
    "expires_at": "2027-11-25T00:00:00Z", // paid period plus 14 days of grace
    "key_id": "..."                     // a key of role "license" in the root
  },
  "signature": "..."                   // Ed25519 by the license key
}
```

- The document holds no customer reference. The license service maps license IDs to MoR customer
  IDs in its order table; nothing that travels with requests names the customer.
- Varde verifies it offline with the license keys of the trusted root (4.4), so license keys
  rotate through the root like feed keys. The gate walks the same root chain to learn them.
- Requests carry `Authorization: Varde-License <base64 of the document>` over TLS. The gate checks
  signature, `not_before`, `expires_at` and the revocation list. It needs only public keys: a
  compromised gate cannot issue licenses.
- **Root files are public.** The gate serves `v1/root.json` and `v1/root/<n>.json` without a
  license. An installation that was switched off through a license key rotation holds an older
  root, so a license signed by the new key would be refused against it. On switch-on Varde
  therefore walks the root chain first, without any credential, and verifies the license against
  the newest root; the license is still never sent before it has been verified. Roots contain
  public keys only, so serving them to anyone reveals nothing.
- The license is a bearer credential. Sharing is limited by the gate (5.4), not by tying the
  license to a machine, which would need an activation server and identify installations.

### 5.2 Sales through a merchant of record

The merchant of record is **Paddle**. It is the seller: it collects payment, charges and remits
VAT in every country, issues invoices, handles refunds and chargebacks. Varde's side is only the
webhook.

Rejected: Lemon Squeezy. Since its acquisition by Stripe, Lemon Squeezy points its merchants
towards Stripe Managed Payments; no end date has been announced, but an integration built now
would likely have to be migrated. Stripe Managed Payments itself is not a full subscription
billing product.

1. The customer buys the subscription on Paddle's checkout page (linked from Varde's settings
   page and the website; no Varde account).
2. Paddle sends a signed webhook (`subscription.created`, `transaction.completed`) to the license
   service. It verifies the signature, issues a license for the paid period plus grace, stores
   `(license, customer, period)` and returns.
3. The customer receives Paddle's receipt with a one-time link (`/l/<random 128-bit token>`,
   valid 30 days, usable three times) to download the license file. The receipt customisation or
   a follow-up e-mail from Paddle carries the link; the license service sends no e-mail.
4. Renewals issue a new license with a new expiry under the same license ID; Varde fetches the
   renewed document from the gate (`/v2/license/<id>`, authenticated with the current one) a week
   before expiry, so renewals need no user action.
5. `subscription.canceled` lets the license run out; `transaction.refunded` and chargebacks put the
   license on the revocation list at once.

### 5.3 Revocation

The license service publishes a revocation list signed with a license key: a sorted list of
license IDs that have not expired yet (expired ones are dropped) and the time it was made. The gate
fetches it every five minutes and refuses a list older than the one it has. If the license service
is down, the gate keeps the last list; nothing stops working.

### 5.4 Abuse without surveillance

The gate keeps, in memory only, per license ID: requests per hour and distinct /24 (IPv4) or /56
(IPv6) prefixes per day. Defaults: 600 requests an hour (one installation needs a few dozen), five
prefixes a day (home, mobile, a second site). Beyond that the gate answers 429 for the hour and
counts the event; a license that keeps exceeding is listed for a human decision, never blocked
automatically for good. Nothing of this is written to disk except daily totals per license ID.

These limits stop casual sharing of one license among many installations. They do not stop a
subscriber from mirroring the feed (6.6).

### 5.5 Price

Recommendation: **EUR 3.49 a month, billed yearly (EUR 41.88)**, optionally a monthly plan at
EUR 3.99. For a security tool the difference between two and four euros does not decide a
purchase; it does decide whether the curation work (4.1, 7) is paid for.

At EU consumer prices (VAT included; 19 % shown, the rate depends on the buyer's country) and
Paddle's 5 % + USD 0.50 (about EUR 0.47) per transaction:

| Billing | Gross | VAT (19 %) | Paddle fee | Payout | Share |
|---|---|---|---|---|---|
| Yearly, 41.88 | 41.88 | 6.69 | 2.56 | **32.63** (2.72 a month) | 78 % |
| Monthly, 3.99 | 3.99 | 0.64 | 0.67 | **2.68** | 67 % |
| For comparison: yearly at 1.99 a month (23.88) | 23.88 | 3.81 | 1.66 | 18.41 (1.53 a month) | 77 % |

The fixed fee per transaction is why yearly billing is the default. Paddle's own price list is to
be confirmed when the account is opened, in particular whether transactions under USD 10 carry
different terms (secondary sources disagree) and its currency conversion margin on payouts.

Running cost, estimated: four small VMs (three builders at three providers, one for gate and
license service), staging and object storage for a few GB with history, one domain: about EUR 30 a
month. Break-even is about 12 yearly subscribers. The operator's time is not in this figure.

## 6. Security

### 6.1 Assets, trust boundaries and the operator

| Asset | Threat if lost | Where it lives |
|---|---|---|
| Root keys (3, threshold 2) | Anyone can redefine every other key | Offline: two hardware tokens (YubiKey 5 series, firmware 5.7.4 or later for Ed25519 in PIV) and one paper key in a safe deposit box |
| Override key (threshold 1) | Acknowledge drops: make clients accept a shrunken feed signed by the feed threshold | A third hardware token, kept apart from the root tokens, used only for acknowledgements |
| Feed keys (one per builder, threshold 2) | With two: sign any feed | On the builders, encrypted at rest (systemd credentials), 90-day validity |
| License keys | Forge licenses or revocation lists (revenue and availability, not integrity) | License service VM only |
| Source credentials (NVD key, GitHub token) | Rate-limit abuse in the project's name | Builders, systemd credentials |
| Paddle webhook secret | Forge purchases | License service |
| Order database | Links license IDs to Paddle customer IDs | License service; no names or e-mail addresses |
| Operator SSH keys | Access to builders | One FIDO2 key per builder (`ed25519-sk`, touch and PIN required), on a token separate from the root and override tokens |

The installations trust only the root they were shipped with. Everything between the builders and
the installations (staging, origin, gate, CDN, mirrors, the network) is untrusted for integrity.

**The operator.** The service is run by one person, who holds both root tokens, the override token
and SSH access to every builder. The thresholds therefore protect against the loss or theft of one
token, the compromise of one builder and the compromise of one provider. They do not protect
against the operator, or against an attacker in full control of the operator's workstation and
tokens. Controls that narrow this: separate SSH keys per builder that require a touch for every
login, no agent forwarding, builders that run only tagged, reproducible releases (a change on one
builder shows as a mismatch, 6.2), no interactive root access in normal operation, and a public
log of every ceremony and acknowledgement (6.4). A second root holder would remove the
single-person limit and is the first thing to add once the project has one.

### 6.2 Threats and controls

| Threat | Control |
|---|---|
| A builder is compromised | It holds one of three feed keys; the threshold needs two. As leader it can hold back record updates for the consistency window, not add, alter or drop records (4.1). It can stop signing; the other two keep publishing |
| Two builders are compromised | Different providers, different credentials, separate SSH keys; only the root holders can recover. Keys rotate through the root; installations follow the root chain |
| One builder or provider is down | The other two reach the threshold; the next builder leads |
| An upstream source is poisoned or truncated (a broken export, a mass withdrawal) | Builders refuse to sign when the record count of a source or an ecosystem drops by more than 5 % or a single run withdraws more than 1 % of records, unless an acknowledgement signed with the override key covers it (6.3) |
| Builders disagree because a source changed between fetches | Not a threat but the normal case; handled by the input snapshot and the cross-check (4.1). Repeated inconsistencies alert |
| The origin, staging or gate is compromised | Cannot alter data (signatures, hashes); can withhold or replay it, which expiry (72 h) and sequence numbers expose; holds no secret that issues licenses or signs feeds |
| A CDN or mirror misbehaves | Same as the origin; they are untrusted transport |
| Rollback or freeze | `sequence` must not decrease; manifests expire after 72 h; the stale notice appears after `VARDE_FEED_STALE_AFTER` |
| Slow truncation (removing a little every hour) | Clients compare counts with a 30-day baseline, not only with the last manifest (6.3) |
| A stolen license | Bearer credential with an expiry; rate and prefix limits; revocation on request |
| A forged license | Ed25519 signature checked by Varde and the gate; the license keys never leave the license service |
| The license service is compromised | Can issue licenses and revoke everyone (revenue and availability); cannot touch feed integrity. Revocation lists are bounded to unexpired licenses, and the gate alerts on a list that revokes more than a threshold at once |
| Webhook forgery or replay | Paddle signature, timestamp within five minutes, idempotency by event ID |
| Denial of service on the gate | Static files, rate limits per license and per IP, a CDN in front if needed; installations keep their last feed and can fall back to direct mode |
| The build tooling is compromised (dependency, compiler) | The builders are built reproducibly from the tagged source with pinned dependencies; builders running the same release must produce the same bytes, so a tampered builder binary on one side shows as a mismatch |
| The operator's workstation is compromised | See 6.1: touch-bound SSH keys per builder, tokens for root and override never attached in normal operation; beyond that, out of reach of the thresholds |
| A Varde release is compromised | Out of scope here; covered by the signed release process (`docs/releasing.md`) |

### 6.3 Detecting what signatures cannot

Signatures prove who published, not that the data is right. Three checks cover the rest:

- **Shrink and churn thresholds** at build time (6.2).
- **Canary**: after each publish a job on a host that shares no credentials with the builders or
  the gate installs the feed with the released Varde client into a fixed test inventory and
  compares the findings with the previous run and with direct mode for the same inventory.
  Differences beyond the expected advisories alert.
- **Client-side plausibility**: Varde keeps, per ecosystem release it uses, the highest record
  count of the manifests it installed in the last 30 days, and refuses a manifest whose count for
  such an ecosystem is more than 20 % below it. Comparing only with the last manifest would let a
  feed shrink by 19 % an hour. It keeps the previous manifest and shows a notice.

**Acknowledgements.** Legitimate large drops happen: a release reaches its end of life, osv.dev
deduplicates records, a source reorganises. An acknowledgement is a small document signed with the
override key: `{ecosystem or source, expected count, valid from sequence, valid until}`. The
manifest references it by hash (`acknowledgements`, 4.3); builders accept the drop it names, and
clients accept a count down to the expected one. Because the override key is not a feed key, a
compromised build pipeline cannot acknowledge its own truncation; because it is not a root key,
routine acknowledgements do not expose the root tokens. Every acknowledgement is published in the
data repository with its reason.

### 6.4 Key ceremonies

- **Signing with the token** is prototyped in phase 2, before any production key exists: raw
  Ed25519 over the exact bytes of `signed`, via PIV on firmware 5.7.4 or later. OpenPGP cards
  through GnuPG sign an OpenPGP signature packet, not arbitrary bytes, and are not used for this.
  Tokens cannot be upgraded to newer firmware, so the tokens bought must already have it.
- **Root creation** (once): on an offline laptop booted from read-only media, generate three root
  keys, write two to hardware tokens and one to paper (base32, printed twice), generate the
  override key on its own token, sign root version 1 listing the root, feed, license and override
  keys in root format 2 (4.4), verify the signatures on a second machine, and embed root 1 in the
  next Varde release.
- **Feed key rotation** (every 90 days, or at once on suspicion): each builder generates a new key
  and sends the public key; two root keys sign a new root version listing it. Installations pick it
  up through the chain walk.
- **License key rotation** (yearly): the license service generates a new key; the root signs a
  root version listing it with role `license`; old licenses stay valid until they expire.
- **Acknowledgements** (6.3): signed with the override token on demand, recorded with a reason.
- Every ceremony follows a written checklist and is recorded in `docs/key-ceremonies.md` (date,
  root version, key IDs, participants), never with key material.

### 6.5 Privacy

What the service can learn, stated plainly:

- The gate sees, per license ID, the ecosystem releases in use, when a new one appears, and the
  network prefixes requests come from (held in memory only). The license document carries no
  customer reference, but the order table maps license IDs to Paddle customer IDs, and Paddle holds
  names. The operator can therefore technically link a customer to the set of ecosystems they use,
  more easily so while gate and license service share a VM. That this is not done is an
  organisational commitment, written into the privacy notice.
- Rejected for v1: unlinkable access tokens (blind signatures in the style of Privacy Pass) that
  would separate "has paid" from "is fetching". They would remove the link technically, at the
  cost of a protocol and a client the project would have to maintain. To be reconsidered if
  subscribers ask for it.

Controls:

- The gate logs no request lines, IP addresses or user agents. It keeps the in-memory counters of
  5.4 and writes daily totals per license ID.
- The license service stores license ID, Paddle customer ID and period, nothing else; Paddle holds
  name, address and payment data.
- TLS only, HSTS, no cookies, no third-party scripts, no CDN that inspects payloads without a
  contract (or none at all at the start).
- Data subject requests are answered from the order table (license ID and period) and forwarded to
  Paddle for the rest.

### 6.6 Redistribution

The feed is built to be mirrored and exported to a directory, and its signature makes any mirror
trustworthy. One subscriber can therefore pass it on, and rate limits do not prevent a mirror that
fetches once an hour. Most of the data is under licenses that allow redistribution (8), so the
terms of service can restrict redistribution only for the project's own content (curated
advisories, normalisation) and only as far as the upstream licenses allow. This is accepted: the
subscription sells convenience, privacy towards upstream sources and curation.

## 7. Operations

| Task | How | Human effort |
|---|---|---|
| Builds | systemd timer every hour on all builders | none |
| Publishing | the second signature on the same bytes completes the manifest; the builder that sees it publishes | none |
| OS updates | unattended upgrades, weekly reboot window, staggered across builders | none |
| Monitoring | the canary, an external uptime check of the gate, inconsistency and mismatch alerts, alerts by ntfy or e-mail | read alerts |
| Backups | the order database, nightly, encrypted (restic) to a storage box; the origin store is versioned | none |
| Curated advisories | YAML files in a separate repository, reviewed and merged; the builders include them | per vendor advisory; measured in phase 1 |
| Acknowledgements | 6.3, when a threshold blocks a legitimate drop | minutes each |
| Releases of the service | tagged, reproducible builds; builders updated one after another within one day | per release |
| Key rotation | ceremonies of 6.4 | about an hour per quarter |
| Abuse review | the list of licenses over their limits | minutes a month |

Recovery: every VM is rebuilt from a cloud-init file and the tagged binaries in under an hour;
only the license service's database and keys need a backup.

Curation is the part that does not automate: turning a prose advisory from Synology, QNAP or AVM
into affected version ranges takes real time per advisory. Phase 1 measures it on a sample before
the price and the list of curated vendors are fixed.

## 8. Legal

### 8.1 Licences of the data

- Every source is checked individually in phase 1, and the result is recorded in the
  `attribution` list with its licence. "Mostly CC-BY-4.0 or public domain" is not enough: a source
  under a ShareAlike licence would put the compacted shards, as derived works, under ShareAlike
  too, and a source without a licence allowing redistribution cannot be included. The OSV data of
  every distribution (Debian, Ubuntu, Alpine, Chainguard, Wolfi and the others) is checked against
  that distribution's own terms, not against osv.dev's.
- Known so far, to be confirmed in the same check: the GitHub Advisory Database is CC-BY-4.0; NVD
  and CISA KEV are public domain, and NVD asks API users to display its notice that the product
  uses NVD data but is not endorsed by NVD; EPSS requires attribution to FIRST; endoflife.date is
  MIT.
- CC-BY-4.0 does not allow additional terms or technical measures that restrict recipients from
  exercising the licensed rights. The terms of service therefore do not forbid passing on the data
  received (6.6).
- CSAF feeds carry per-vendor terms; only feeds that allow redistribution are included.
- Exploit signals are references (IDs and links), not exploit code.

### 8.2 Cyber Resilience Act

The CRA (Regulation (EU) 2024/2847) treats free and open-source software as outside its scope
unless it is made available in the course of a commercial activity, and Recital 15 counts the
monetisation of related services among the signs of commercial activity. A paid data subscription
for Varde may turn Varde into a product made available commercially, with its developer as the
manufacturer. That would bring the vulnerability-reporting obligations of Article 14, which apply
since 11 September 2026, and the remaining obligations from 11 December 2027.

Arguments that the subscription is separate: Varde is identical with and without it, works
completely in direct mode and gates no feature; the subscription is a data service, not software.
Whether this separation holds is not settled by this document. It is assessed before phase 5,
with the Commission's guidance on monetisation of other services and, if needed, legal advice. The
outcome decides whether Varde's release and vulnerability process (`SECURITY.md`,
`docs/releasing.md`) has to be brought to manufacturer level; much of that is worth doing either
way.

### 8.3 Other

- Paddle's terms cover the sale; the subscription needs its own short terms of service and a
  privacy notice stating 6.5. An imprint is required for the website.

## 9. What the maintainer needs to provide

1. A business identity for Paddle (it verifies the seller).
2. A domain for the gate and the license service.
3. Accounts at three hosting providers (EU-based where possible) and a storage box.
4. Hardware tokens, YubiKey 5 series with firmware 5.7.4 or later: two for the root keys, one for
   the override key, one for daily SSH access (plus a spare); and a safe place for the paper key.
5. Terms of service, privacy notice and imprint (Paddle provides templates for the sales part).
6. The CRA assessment of 8.2, before phase 5.

## 10. Build plan

| Phase | Content | Exit criterion |
|---|---|---|
| 1. Measure | Builder prototype that downloads the exports and writes compacted shards and indexes; sizes per ecosystem release (Chainguard and Wolfi in particular), manifest and index sizes, upstream change rate per hour, how often two independent fetches disagree; licence of every source (8.1); curation time on a sample of vendor advisories | Real sizes per release and per typical installation; a sized consistency window; a licence table; a measured curation cost |
| 2. Formats | Root format 2 (roles, thresholds, evolution rule, 4.4) and manifest format 2 (indexes, acknowledgements, 4.3) in the client; ecosystem selection, name normalisation, the 30-day plausibility baseline; signing prototype with a 5.7.4 token; development roots only | A lab installation runs on a locally built format-2 feed with the same findings as direct mode; a root with an unknown role verifies, a root with an unknown field does not |
| 3. Three builders | Input snapshot, cross-check, leader rotation, staging, determinism, two-of-three signatures, shrink thresholds and acknowledgements, publishing to the origin | Three builders at different providers publish identical, doubly signed feeds; one builder switched off does not stop publishing; an injected inconsistency is refused |
| 4. Gate and licenses | Gate, license documents, revocation list, license service with the Paddle sandbox | A sandbox purchase yields a license that a lab installation uses; a refund revokes it |
| 5. Production | CRA assessment done, root ceremony, embedded root in a Varde release, canary, monitoring, terms | First paying subscriber |

Each phase is one pull request in this repository (the builders, the gate and the license
service live in `cmd/`), except the curated advisories and acknowledgements, which get their own
data repository.
