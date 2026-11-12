# 0010 License: Apache-2.0

Status: Accepted

## Context
Decided by the maintainer; consistent with the maintainer's other projects. Apache-2.0 carries an explicit
patent grant and is compatible with the expected dependency set.

## Decision
All code under Apache-2.0. Every source file carries `SPDX-License-Identifier: Apache-2.0`,
enforced by `scripts/check-license-headers.sh` in CI. `NOTICE` holds attribution.

## Alternatives
- MIT: no patent grant.
- AGPL: discourages integration, not desired.

## Consequences
Dependencies must be Apache-2.0 compatible (MIT, BSD, ISC, Apache-2.0, MPL-2.0 at file level).
Checked when a dependency is added and recorded in `docs/dependencies.md`.
