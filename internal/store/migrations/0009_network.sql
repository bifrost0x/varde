-- SPDX-License-Identifier: Apache-2.0
-- Network discovery and agentless integrations (ADR 0020).

-- Devices found by a network scan, one row per address.
CREATE TABLE devices (
    address       TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL,
    label         TEXT NOT NULL,
    services_json TEXT NOT NULL DEFAULT '[]',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL
) STRICT;

-- Connections to platforms through their official interfaces. config_json
-- holds non-secret settings (address, user, pinned key or certificate);
-- secret holds credentials encrypted with the key in <data>/keys.
CREATE TABLE integrations (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    name         TEXT NOT NULL,
    address      TEXT NOT NULL,
    config_json  TEXT NOT NULL DEFAULT '{}',
    secret       BLOB,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_by   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_success INTEGER,
    last_error   TEXT NOT NULL DEFAULT '',
    status_json  TEXT NOT NULL DEFAULT '{}',
    UNIQUE (kind, address)
) STRICT;

ALTER TABLE hosts ADD COLUMN integration_id TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN detail TEXT NOT NULL DEFAULT '';
