# 0009 Direct and feed mode share one model and one engine

Status: Accepted

## Context
Direct mode (client queries upstreams) is needed before the central feed exists, and remains useful
for local catalog entries.

## Decision
Both modes populate the same OSV-based `AdvisoryStore` through the `AdvisorySource` interface. The
feed is one source among others. Matching, policy and notification do not know where data came from
beyond the recorded evidence.

## Alternatives
- Separate pipelines per mode: duplicated logic, diverging results.

## Consequences
Hybrid mode is a source configuration, not a code path. Tests can assert identical findings for the
same data delivered through either mode.
