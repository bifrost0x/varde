-- SPDX-License-Identifier: Apache-2.0
-- Agents (enrollment tokens, pinned certificates, liveness) and system
-- notices (coverage gaps and hosts that stopped reporting).

CREATE TABLE enrollment_tokens (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    host_id    TEXT
) STRICT;

-- agent_cert_fingerprint (from 0001) is the SHA-256 of the pinned client
-- certificate. During rotation the new certificate is pending until the agent
-- uses it once; until then the old one stays valid.
ALTER TABLE hosts ADD COLUMN agent_cert_expires INTEGER;
ALTER TABLE hosts ADD COLUMN agent_cert_pending TEXT;
ALTER TABLE hosts ADD COLUMN agent_cert_pending_expires INTEGER;
ALTER TABLE hosts ADD COLUMN report_interval_ms INTEGER NOT NULL DEFAULT 0;
-- Hash of the last snapshot accepted from an agent; heartbeats refer to it.
ALTER TABLE hosts ADD COLUMN snapshot_hash TEXT NOT NULL DEFAULT '';

CREATE TABLE notices (
    key         TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    subject     TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    resolved_at INTEGER,
    notified_at INTEGER
) STRICT;

CREATE INDEX notices_active ON notices (kind) WHERE resolved_at IS NULL;
