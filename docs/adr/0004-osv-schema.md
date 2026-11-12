# 0004 OSV schema for advisory records

Status: Accepted

## Context
Advisories come from GitHub (GHSA), OSV, NVD and project-specific sources with different shapes.

## Decision
Store every advisory as an OSV record (https://ossf.github.io/osv-schema/). Source-specific fields
are mapped on import; the original identifier and aliases are kept. Varde-specific data (app ID,
enrichment) lives in `database_specific` or in separate columns, never in altered standard fields.

## Alternatives
- Own schema: freedom, but re-invents range semantics and loses interoperability.
- CSAF: heavier, aimed at vendor advisories, poor fit for open-source app releases.

## Consequences
Range evaluation follows OSV semantics (`SEMVER`, `ECOSYSTEM`, `versions` lists; `GIT` ignored with
a logged reason). The feed pipeline can reuse existing OSV tooling.
