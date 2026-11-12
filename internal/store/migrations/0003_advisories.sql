-- SPDX-License-Identifier: Apache-2.0
-- Advisory data (OSV records per app and source), enrichment, per-source
-- refresh state, and findings.

CREATE TABLE advisories (
    app_id         TEXT NOT NULL,
    source         TEXT NOT NULL,
    id             TEXT NOT NULL,
    osv_json       TEXT NOT NULL,
    modified       INTEGER NOT NULL,
    withdrawn      INTEGER,
    aliases_json   TEXT NOT NULL DEFAULT '[]',
    severity_cvss  REAL,
    severity_label TEXT NOT NULL DEFAULT '',
    fetched_at     INTEGER NOT NULL,
    PRIMARY KEY (app_id, source, id)
) STRICT;

CREATE TABLE kev (
    cve_id     TEXT PRIMARY KEY,
    date_added TEXT NOT NULL DEFAULT '',
    ransomware TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL,
    date       TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE source_state (
    source        TEXT NOT NULL,
    key           TEXT NOT NULL,
    etag          TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    last_attempt  INTEGER,
    last_success  INTEGER,
    last_error    TEXT NOT NULL DEFAULT '',
    next_run      INTEGER,
    PRIMARY KEY (source, key)
) STRICT;

CREATE TABLE findings (
    id                     TEXT PRIMARY KEY,
    workload_id            TEXT NOT NULL REFERENCES workloads (id) ON DELETE CASCADE,
    app_id                 TEXT NOT NULL,
    advisory_id            TEXT NOT NULL,
    match_state            TEXT NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'open',
    priority               TEXT NOT NULL DEFAULT '',
    exposure               TEXT NOT NULL DEFAULT '',
    fixed_in               TEXT NOT NULL DEFAULT '',
    detail_json            TEXT NOT NULL,
    first_seen             INTEGER NOT NULL,
    last_changed           INTEGER NOT NULL,
    resolved_at            INTEGER,
    snoozed_until          INTEGER,
    notified_at            INTEGER,
    last_notified_priority TEXT NOT NULL DEFAULT '',
    UNIQUE (workload_id, advisory_id)
) STRICT;

CREATE INDEX findings_open ON findings (state) WHERE state <> 'resolved';
