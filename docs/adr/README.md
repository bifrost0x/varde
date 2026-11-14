# Architecture decision records

Format: context, decision, alternatives, consequences. Status is one of Proposed, Accepted,
Superseded by NNNN. Records are not edited after acceptance except to change the status.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-go-static-binary.md) | Go, single static binary | Accepted |
| [0002](0002-sqlite-pure-go.md) | SQLite via pure-Go driver | Accepted |
| [0003](0003-pull-and-match-locally.md) | Pull and match locally, no inventory upload | Accepted |
| [0004](0004-osv-schema.md) | OSV schema for advisories | Accepted |
| [0005](0005-feed-trust.md) | Feed trust: minimal signed manifest instead of go-tuf v2 | Accepted |
| [0006](0006-docker-socket-proxy.md) | Docker access only via GET-only socket proxy | Accepted |
| [0007](0007-server-rendered-ui.md) | Server-rendered UI with htmx, embedded assets | Accepted |
| [0008](0008-precision-first-matching.md) | Precision-first matching | Accepted |
| [0009](0009-shared-model-direct-feed.md) | Direct and feed mode share model and engine | Accepted |
| [0010](0010-license-apache-2.md) | Apache-2.0 license | Accepted |
| [0011](0011-one-binary-agent-mtls.md) | One binary, agents push over mTLS | Accepted |
| [0012](0012-coverage-as-feature.md) | Coverage as a product feature | Accepted |
| [0013](0013-design-system-first.md) | Brand and design system before UI | Accepted |
| [0014](0014-identity-configuration-points.md) | Product identity configuration points | Accepted |
| [0015](0015-catalog-data-license.md) | Catalog data license | Accepted |
| [0016](0016-stdlib-docker-client.md) | Minimal read-only Docker client | Accepted |
| [0017](0017-advisory-coverage-strategy.md) | Advisory coverage for apps without structured advisories | Accepted |
| [0018](0018-authentication.md) | Authentication, sessions and request integrity | Accepted |
| [0019](0019-agent-protocol.md) | Agent protocol details | Accepted |
| [0020](0020-agentless-integrations.md) | Agentless first: network discovery and official integrations | Accepted |
| [0021](0021-hosts-from-evidence.md) | One host record built from the evidence of every source | Accepted |
| [0022](0022-native-packages-and-version-endpoints.md) | Native packages over SSH and version endpoints | Accepted |
| [0023](0023-evidence-trust-and-measurement.md) | Evidence, trust, stable assets and measured recognition | Accepted |
| [0024](0024-low-friction-onboarding.md) | Onboarding through few, narrow connections | Accepted |
| [0025](0025-registry-versions-and-derived-apps.md) | Versions from the registry and apps derived from source labels | Accepted |
| [0026](0026-image-package-databases.md) | Package databases and app manifests of images | Accepted |
| [0027](0027-container-drift.md) | Container drift | Accepted |
| [0028](0028-distribution-security-data.md) | Distribution security data and VEX | Accepted |
| [0029](0029-remediation.md) | Remediation: concrete updates, end of life, more channels, tour, resolved findings | Accepted |
| [0030](0030-full-inventory.md) | The full inventory of hosts and guests | Accepted |
| [0031](0031-agent-install-and-update.md) | The agent reads the full host inventory, is installed by Varde and updates itself | Accepted |
| [0032](0032-system-packages.md) | Every installed package is checked against its distribution's security data | Accepted |
| [0033](0033-image-packages.md) | The packages of container images are checked, also through agents | Accepted |
| [0034](0034-attack-paths.md) | Attack paths tell exploitable findings from background noise | Accepted |
| [0035](0035-finding-history.md) | Findings keep their identity and history; the UI groups them by what fixes them | Accepted |
| [0036](0036-wider-detection.md) | Wider detection: language packages, more distributions, appliances, local discovery | Accepted |
| [0037](0037-feed-service.md) | The central feed service and the paid data subscription | Proposed |
| [0038](0038-universal-recognition-and-uplink-switch.md) | Look up instead of guess, and one installation for free and paid use | Accepted |
| [0039](0039-daily-data-package.md) | One signed data package a day, the same knowledge for everyone | Accepted |
| [0040](0040-generated-catalog-and-release-fixes.md) | Generated catalog entries and release fixes | Accepted |
| [0041](0041-release-tags-in-the-data-package.md) | Release tags in the data package | Accepted |
