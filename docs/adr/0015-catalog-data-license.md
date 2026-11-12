# 0015 Catalog data license

Status: Accepted

## Context
The catalog is community-maintained data that third parties (other tools, the central feed) should
be able to reuse. The default was Apache-2.0 unless the maintainer decided otherwise.

## Decision
Catalog data is licensed Apache-2.0, like the code. Contributions are accepted under the same terms
(inbound = outbound, no CLA).

## Alternatives
- CC0 or CDLA-Permissive-2.0: data-specific and simpler for reuse, but a second license to explain.
- CC BY-SA: share-alike would hinder integration into other tools.

## Consequences
One license for the whole repository. The maintainer can revisit this before the catalog moves to its own
repository (`varde/catalog`).
