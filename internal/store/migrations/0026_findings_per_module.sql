-- SPDX-License-Identifier: Apache-2.0
-- A Go or npm advisory naming several modules of one program is one
-- finding per module (FindingInput.ID), so a workload can hold the same
-- advisory more than once. The UNIQUE (workload_id, advisory_id) of 0003
-- refused the second one and stopped the analysis. SQLite cannot drop a
-- table constraint, so the table is rebuilt with every row and column;
-- the ID stays the primary key. No other table references findings.
CREATE TABLE findings_new (
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
    priority_reason        TEXT NOT NULL DEFAULT '',
    exposure_evidence_json TEXT NOT NULL DEFAULT '[]',
    acknowledged_at        INTEGER,
    suppression_id         TEXT NOT NULL DEFAULT '',
    digest_pending         TEXT NOT NULL DEFAULT '',
    path_class             TEXT NOT NULL DEFAULT '',
    path_reason            TEXT NOT NULL DEFAULT ''
) STRICT;

INSERT INTO findings_new (id, workload_id, app_id, advisory_id, match_state, state, priority, exposure, fixed_in,
    detail_json, first_seen, last_changed, resolved_at, snoozed_until, notified_at, last_notified_priority,
    priority_reason, exposure_evidence_json, acknowledged_at, suppression_id, digest_pending, path_class, path_reason)
SELECT id, workload_id, app_id, advisory_id, match_state, state, priority, exposure, fixed_in,
    detail_json, first_seen, last_changed, resolved_at, snoozed_until, notified_at, last_notified_priority,
    priority_reason, exposure_evidence_json, acknowledged_at, suppression_id, digest_pending, path_class, path_reason
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

CREATE INDEX findings_open ON findings (state) WHERE state <> 'resolved';
CREATE INDEX findings_workload ON findings (workload_id, advisory_id);
