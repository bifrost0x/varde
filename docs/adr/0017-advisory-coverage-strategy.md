# 0017 Advisory coverage for apps without structured advisories

Status: Accepted

## Context
Some popular self-hosted apps publish no GitHub repository advisories at all (e.g. Nginx Proxy
Manager, Radarr, Mosquitto); their vulnerabilities appear only as CVEs, in release notes or on
mailing lists. One option was to list them as "inventory-only". The maintainer decided: include them,
and do everything possible to obtain advisory data for them instead of giving up.

## Decision
Every catalog entry declares `advisories.coverage` (`full`, `partial`, `limited`) and lists every
source that exists. Sources form a ladder, used together, not as alternatives:

1. GitHub repository security advisories (`github_repos`), including sibling repositories.
2. GitHub global advisory database / OSV for the packages the app ships as (`osv_packages`).
3. CVE databases via CPE (`cpe`): NVD now, EUVD in the central pipeline. In direct mode an NVD
   source queries only the CPEs of apps actually present (opt-in like OSV because it reveals
   which apps run).
4. Release notes and security pages (`notes`): curated into OSV records by the central feed
   pipeline (v2); the catalog records where to look.

CVE-derived ranges from CPE configurations are less precise than repository advisories. Findings
built on them carry that provenance in their evidence, and an incomparable or missing range yields
`unverified`, never `affected` (ADR 0008).

The UI shows the coverage level per app, so `limited` is never mistaken for "no known issues".

## Alternatives
- Inventory-only entries: honest, but leaves users of these apps without any signal.
- Scraping release notes in the client: fragile, high false-positive risk; belongs in the central,
  reviewed pipeline.

## Consequences
Direct mode has an NVD source (opt-in, rate limited, optional API key via `_FILE`). The feed
pipeline gains a curation step for release-note advisories. Coverage claims are reviewable per
entry.
