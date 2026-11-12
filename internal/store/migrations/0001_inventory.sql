-- SPDX-License-Identifier: Apache-2.0
-- Hosts and workloads. Timestamps are Unix milliseconds (UTC).

CREATE TABLE hosts (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    kind                   TEXT NOT NULL,
    source                 TEXT NOT NULL,
    agent_cert_fingerprint TEXT,
    agent_version          TEXT NOT NULL DEFAULT '',
    os                     TEXT NOT NULL DEFAULT '',
    arch                   TEXT NOT NULL DEFAULT '',
    addresses_json         TEXT NOT NULL DEFAULT '[]',
    state                  TEXT NOT NULL DEFAULT 'active',
    last_contact           INTEGER NOT NULL,
    created_at             INTEGER NOT NULL
) STRICT;

CREATE TABLE workloads (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    runtime_id      TEXT NOT NULL,
    name            TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT '',
    -- Query columns; the complete kind-specific record lives in data_json.
    image_ref       TEXT NOT NULL DEFAULT '',
    image_digest    TEXT NOT NULL DEFAULT '',
    package_name    TEXT NOT NULL DEFAULT '',
    package_version TEXT NOT NULL DEFAULT '',
    unit_name       TEXT NOT NULL DEFAULT '',
    data_json       TEXT NOT NULL,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    removed_at      INTEGER,
    UNIQUE (host_id, kind, runtime_id)
) STRICT;

CREATE INDEX workloads_active ON workloads (host_id, kind) WHERE removed_at IS NULL;
CREATE INDEX workloads_removed ON workloads (removed_at) WHERE removed_at IS NOT NULL;
