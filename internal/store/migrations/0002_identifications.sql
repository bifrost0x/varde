-- SPDX-License-Identifier: Apache-2.0
-- Identification of workloads against the catalog, recomputed after every
-- inventory change and on catalog load.

CREATE TABLE identifications (
    workload_id    TEXT PRIMARY KEY REFERENCES workloads (id) ON DELETE CASCADE,
    app_id         TEXT NOT NULL DEFAULT '',
    confidence     TEXT NOT NULL,
    rule           TEXT NOT NULL DEFAULT '',
    version        TEXT NOT NULL DEFAULT '',
    version_raw    TEXT NOT NULL DEFAULT '',
    version_source TEXT NOT NULL DEFAULT '',
    note           TEXT NOT NULL DEFAULT '',
    updated_at     INTEGER NOT NULL
) STRICT;

CREATE INDEX identifications_app ON identifications (app_id) WHERE app_id <> '';
