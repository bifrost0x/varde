# 0002 SQLite via pure-Go driver, WAL mode

Status: Accepted

## Context
State (inventory, findings, suppressions, sessions, source cursors) is small and local. An external
database would contradict the two-container deployment goal.

## Decision
SQLite through the pure-Go driver `modernc.org/sqlite`, chosen after checking its release and
maintenance state. WAL mode, `busy_timeout`,
`foreign_keys=ON`, embedded forward-only SQL migrations, each applied in one transaction.

## Alternatives
- `mattn/go-sqlite3`: requires CGO, violates 0001.
- Embedded KV stores (bbolt, Pebble): no SQL, more application code for queries and migrations.
- PostgreSQL: extra service, operational burden for homelab users.

## Consequences
Single writable file under `/data`. The modernc driver is a large transpiled code base; its size and
supply-chain surface are accepted and tracked via govulncheck and Dependabot.
