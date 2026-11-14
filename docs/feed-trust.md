# Feed trust

How Varde verifies the central advisory feed (ADR 0005). The client lives in `internal/feed`.

## Layout

A feed is a set of static files, served by any web server or CDN, or copied into a directory or
tarball for air-gapped hosts:

```
v1/root.json                  latest trust root (signed by root keys)
v1/root/<n>.json              every root version, for the chain walk
v1/manifest.json              current snapshot (signed by feed keys)
v1/manifest.json.sig          its signatures
v1/blobs/sha256/<hex>         content-addressed blobs, zstd-compressed
```

Blobs: `catalog` (the catalog entries), `advisories/shard-NN` (OSV records as JSON lines, sharded by
app ID so one new advisory changes one small blob), `enrichment/kev`, `enrichment/epss`.

## Keys and roots

- Ed25519 only. A key ID is the SHA-256 of the raw public key.
- `root.json` is `{"signed": {...}, "signatures": [...]}`; signatures cover the exact bytes of
  `signed`. It lists keys with role `root` or `feed` (feed keys may have validity windows), the
  thresholds for both roles, a version and an expiry, and its environment (`production` or
  `development`).
- Further roles: `license` keys sign uplink licenses, `override` keys sign acknowledgements of
  legitimate drops (ADR 0037). Each role only counts for its own purpose: a license key never
  signs a manifest. Keys with a role a client does not know are ignored and never counted, so a
  later role does not strand clients released before it; unknown fields remain an error.
- A client trusts one root at a time, stored in `<data>/feed/root.json`. The initial root comes from
  `VARDE_FEED_ROOT_FILE`; the official root will be embedded in the binary once the central feed
  exists.
- Root rotation: root `n+1` must be signed by the root threshold of root `n` and of root `n+1`. The
  client fetches `root.json`, and for every version between the trusted one and the latest
  `root/<n>.json`, verifying and storing each step. A mirror offering an older root is rejected.
- Feed key compromise: publish a new root without the key. Clients fetch the root before the
  manifest, so the old key stops counting on the next update.

## Update algorithm

1. Walk the root chain (above); the trusted root must not be expired.
2. Conditional GET of `manifest.json`. A 304 is accepted only while the applied manifest has not
   expired.
3. Verify the manifest signatures against the feed keys valid now; reject otherwise. A manifest
   with a higher `schema_version` than this version reads is refused as "too old for the current
   data package". Check the structure: well-formed blob names, a catalog blob, and for the blobs
   this version reads their media types and sizes, total unpacked size below 256 MB. A blob with
   a well-formed name this version does not know is skipped, neither fetched nor an error: the
   package can grow without breaking older installations. The manifest is signed as a whole, so a
   skipped blob takes nothing from the integrity of the rest.
4. Reject `expires_at` in the past (freeze) and `created_at` more than an hour in the future.
5. Reject a `sequence` lower than the newest one ever applied from the same channel (rollback),
   and the same sequence with different bytes (mix-and-match). The same sequence and bytes of the
   installed manifest is "unchanged".
6. For each blob not in the cache: download at most `size` bytes, check length and SHA-256 before
   decompressing, decompress with a hard limit of `uncompressed_size`, parse strictly (unknown
   fields rejected, IDs and scores validated), build the catalog.
7. Apply in one database transaction (feed advisories, KEV, EPSS, feed state; a lower sequence is
   refused here too), then write the manifest files, keeping the previous ones, activate the
   catalog and remove blobs neither manifest references.
8. Any failure leaves the previous verified state active. Mirrors are tried in order; they are
   untrusted, so a failing or malicious mirror only costs time.

After a restart the installed manifest is verified again and its catalog loaded from the blob
cache, so the server works without network. If the server stopped between the database
transaction and the file write, the database is ahead of the files and the next update reinstalls
the same sequence.

When no manifest verified for `VARDE_FEED_STALE_AFTER` (default 72 h), or the installed one has
expired, a system notice appears on the front page and in the daily digest.

## Channels

One client reads the feed from one of several channels: the data package (`package`), the uplink
(`uplink`), or the feed of the static modes (`feed`). Channels share the trust root and the
format. Each has its own mirrors and its own rollback floor: the newest sequence, with the hash
of its manifest, ever applied from that channel. Returning from the uplink to the data package is
therefore not refused although the package's sequence is lower, while a replay inside one channel
still is. The installed manifest only counts as "unchanged" for the channel it came from; after a
switch the picked channel is installed afresh. The license header goes to the uplink mirrors only.
All channels are signed by the same feed keys, so the signed manifest names its channel
(`"channel"`): the client refuses a manifest of another channel, and a mirror of one cannot serve
an old manifest of the other as its first.

The index blob (`index`, the first-party index of ADR 0038) is validated like the table built into
the binary; a package with a malformed index is refused as a whole.

## Modes

- unset (default): the data package where this build has a trust root (see
  [configuration.md](configuration.md#the-data-package)), otherwise as `direct`.
- `direct`: Varde queries the upstream sources itself.
- `feed`: only the feed.
- `hybrid`: the feed, plus direct sources for apps whose catalog entry does not come from the feed
  (local entries, apps the feed has not added yet). KEV and EPSS come from the feed.

## Licenses and the uplink switch

A license is `{"signed": {"license", "plan", "not_before", "expires_at", "key_id"}, "signature"}`,
signed by a `license` key of the trusted root; it names no customer. Varde verifies it offline
(`(*Root).VerifyLicense`): signature, key validity, plan, validity period with one hour of clock
tolerance. `internal/uplink` holds the state of the switch under Settings: a switch-on verifies
the license, then needs one successful feed update that carries it; expiry, switching off or an
unreadable stored license return to direct mode, removing the feed's advisories and restoring the
built-in catalog. The stored feed sequence survives leaving, so returning cannot be used to roll
back. Not built yet, because they need the service: automatic renewal and the revocation list.

## Development feeds

`cmd/feedbuilder` writes a feed signed with development keys from a catalog and an existing Varde
database (`-from-db`), and with `-license <file>` a development license. It only builds with `-tags feeddev`; CI checks that neither the server nor
its packages use that tag. Its roots say `"environment": "development"`; the server refuses them, initially and in a
rotation, unless `VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true` is set, and then logs a warning.

```sh
go run -tags feeddev ./cmd/feedbuilder -keys ./dev-keys -out ./feed -from-db ./varde.db
VARDE_MODE=feed VARDE_FEED_URLS=file:///feed VARDE_FEED_ROOT_FILE=/dev-keys/root.json   VARDE_FEED_ALLOW_DEVELOPMENT_ROOT=true varde server
```

## What this protects against

- A compromised mirror, CDN or network path: cannot inject or alter advisories (signatures, hashes),
  cannot roll the client back (sequence), cannot freeze it unnoticed (expiry, stale notice), cannot
  exhaust memory or disk (size limits before and during decompression).
- A stolen feed key: limited to its validity window and revocable by a new root.

## What it does not protect against

- A compromised signing pipeline that publishes a validly signed but incomplete or wrong feed.
- A compromised root key threshold.
- Suppression of updates for less than the manifest lifetime: an attacker who blocks all mirrors
  delays new advisories until the manifest expires and the stale notice appears.
- Upstream data errors: the feed passes on what GitHub, NVD, OSV, CISA and FIRST publish.
