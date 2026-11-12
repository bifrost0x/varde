-- SPDX-License-Identifier: Apache-2.0
-- Finding lifecycle (suppressions, digest queue), notification log and
-- audit log.

CREATE TABLE suppressions (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL,
    workload_id TEXT NOT NULL DEFAULT '',
    advisory_id TEXT NOT NULL,
    reason      TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER
) STRICT;

CREATE TABLE notification_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    channel          TEXT NOT NULL,
    kind             TEXT NOT NULL,
    finding_ids_json TEXT NOT NULL DEFAULT '[]',
    sent_at          INTEGER NOT NULL,
    status           TEXT NOT NULL,
    error            TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX notification_log_sent ON notification_log (sent_at);

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
) STRICT;

ALTER TABLE findings ADD COLUMN priority_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN exposure_evidence_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE findings ADD COLUMN acknowledged_at INTEGER;
ALTER TABLE findings ADD COLUMN suppression_id TEXT NOT NULL DEFAULT '';
-- Priority queued for the next digest ('P2', 'P3'), empty when nothing is pending.
ALTER TABLE findings ADD COLUMN digest_pending TEXT NOT NULL DEFAULT '';
