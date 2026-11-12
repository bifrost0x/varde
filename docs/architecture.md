# Architecture

Varde is one Go binary (ADR 0001) with two modes. `varde server` inventories Docker hosts,
identifies the apps, matches them against advisories, prioritises the findings and notifies.
`varde agent` runs on further Docker hosts and pushes their inventory to the server. State lives in
one SQLite file (ADR 0002); the UI is server-rendered (ADR 0007).

```
                       ┌──────────────────────────── varde server ───────────────────────────┐
 Docker ── socket ──── │ inventory ─┐                                                         │
 (read-only proxy)     │            │                                                         │
 agents ─── mTLS ───── │ fleet ─────┼─► store (SQLite) ◄── sources / feed ◄── GitHub, KEV,    │
 :8443                 │            │        │                               EPSS, OSV, NVD,  │
                       │            ▼        ▼                               or signed feed   │
                       │      pipeline: identify → match → exposure → policy                  │
                       │            │        │                                                │
                       │            ▼        ▼                                                │
                       │       coverage    notify ──► ntfy, Gotify, webhook, SMTP            │
                       │       notices                                                       │
 browser, API ── :8080 │ web (UI, auth) + api (REST v1) + /metrics                           │
                       └──────────────────────────────────────────────────────────────────────┘
```

## Flow

1. **Inventory.** `inventory.Syncer` drives a `Collector`: the Docker collector
   (`internal/inventory/docker`, a GET-only stdlib client, ADR 0016) lists containers through the
   socket proxy (ADR 0006), reacts to Docker events (debounced) and resyncs periodically. The store
   applies each snapshot in one transaction and reports what changed. Agents reuse the same syncer
   and collector; their "store" is the mTLS client in `internal/agent`, and the server side
   (`internal/fleet`) applies their snapshots under the host ID from the client certificate.
   Manual entries cover appliances.
2. **Identification** (`internal/identify`, `internal/catalog`, `internal/imageref`,
   `internal/version`): a workload becomes an app of the catalog by label override, image match or
   OCI source label, with a confidence; the running version comes from labels or tags and
   is normalised to the app's version scheme, or from the registry and the image's package database
   (ADR 0025, ADR 0026). Floating tags give no version on their own. Every observation is
   kept as evidence, and the version gets a trust level: only a confirmed version can be affected
   (ADR 0023).
3. **Advisories.** In direct mode `internal/advisory/sources` fetches GitHub repository advisories,
   CISA KEV and FIRST EPSS, and optionally OSV and NVD, only for apps that are present (ADR 0009,
   ADR 0017). In feed mode `internal/feed` installs a signed snapshot (ADR 0005,
   `docs/feed-trust.md`); hybrid uses both. Everything is stored as OSV (ADR 0004).
4. **Matching** (`internal/match`): advisories are deduplicated by alias, version ranges evaluated
   precisely; anything not comparable is `unverified`, never `affected` (ADR 0008). Distribution
   packages are matched against their distribution's records with the dpkg or apk version order
   (`internal/distro`, ADR 0028). `GET /api/v1/vex` exports the findings as OpenVEX.
5. **Assessment** (`internal/exposure`, `internal/policy`): exposure from labels, Traefik routes and
   port bindings; priority from the matrix P1/P2/P3 with configurable thresholds.
6. **Lifecycle and notifications** (`internal/store`, `internal/notify`): findings are opened,
   acknowledged, snoozed, suppressed and resolved; P1 is sent at once, P2 and P3 in digests, and a
   finding is notified again only when its priority rises.
7. **Coverage** (`internal/coverage`): blind spots become system notices separate from findings
   (ADR 0012): public routes Varde cannot assess, agents that stopped reporting and integrations
   that have not read for three intervals; the feed client
   adds a notice when the feed is stale. It also merges stored hosts and scanned devices into one
   record per machine (ADR 0021) and computes the workload coverage; `internal/status` counts the
   findings. Every page, the API and the notices take their numbers from these two packages.

`internal/pipeline` runs steps 2 to 7 after every inventory or advisory change; runs are serialised.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/varde` | Commands, wiring, graceful shutdown |
| `cmd/feedbuilder` | Development feeds (`-tags feeddev` only) |
| `internal/config` | Environment configuration, validated at start |
| `internal/settings` | Layered settings: defaults < UI < environment |
| `internal/store` | SQLite, embedded forward-only migrations |
| `internal/inventory`, `…/docker` | Model, syncer, Docker collector |
| `internal/agent`, `internal/fleet`, `…/wire` | Agent client; server side (CA, listener, enrollment); shared protocol |
| `internal/catalog`, `internal/identify`, `internal/imageref`, `internal/version` | Catalog, identification, versions |
| `internal/advisory`, `…/sources`, `internal/feed` | OSV model, ranges, CVSS; direct sources; feed client |
| `internal/match`, `internal/exposure`, `internal/policy` | Matching, exposure, priorities |
| `internal/pipeline`, `internal/coverage`, `internal/notify` | Analysis; host merge, coverage and blind spots; notifications |
| `internal/status` | Finding counts and the overall state shown by the UI and the API |
| `internal/purl` | Package URLs of images and native packages |
| `internal/eval` | Recognition measurement against the corpus, gate for CI (ADR 0023) |
| `internal/auth`, `internal/web`, `internal/api` | Accounts, sessions, CSRF, tokens; UI; REST API |
| `internal/httpx` | Hardened outbound HTTP client (timeouts, size caps, same-host redirects, egress allowlist) |

## Concurrency

One goroutine per long-running worker (inventory syncer, advisory refresher, notifier, liveness,
housekeeping, the two HTTP servers), all stopped through one context on shutdown. Notifications are
delivered asynchronously with bounded retries and in-flight de-duplication. The catalog is held in
an atomic pointer (`catalog.Live`) so a feed can replace it while requests read it.

## Persistence

`<VARDE_DATA_DIR>` holds `varde.db` (WAL), `ca/` (agent CA, key 0600) and `feed/` (trusted root,
active and previous manifest, blob cache). Migrations are embedded and forward-only. Retention:
notification log 30 days, resolved findings and removed workloads 90 days.

## Security boundaries

See `docs/threat-model.md`. In short: Docker only through a read-only proxy; agents only with a
pinned client certificate; the UI and API only with a session or token; outbound requests only
through `httpx`; upstream text is escaped and shown as plain text.
