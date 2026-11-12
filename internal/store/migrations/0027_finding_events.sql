-- SPDX-License-Identifier: Apache-2.0
-- What happened to each finding: opened, reopened, resolved and why. The
-- rows copy the names they show, so the history stays readable after the
-- workload or host is purged; there is deliberately no foreign key.
CREATE TABLE finding_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    TEXT NOT NULL,
    at            INTEGER NOT NULL,
    -- opened, reopened, resolved
    kind          TEXT NOT NULL,
    -- For resolved: updated (the version changed), removed (the workload
    -- is gone), uninstalled (the package or app is gone from the
    -- workload), advisory (same version, the advisory no longer applies),
    -- or empty when not known.
    cause         TEXT NOT NULL DEFAULT '',
    host_id       TEXT NOT NULL DEFAULT '',
    host_name     TEXT NOT NULL DEFAULT '',
    workload_id   TEXT NOT NULL,
    workload_name TEXT NOT NULL DEFAULT '',
    image_ref     TEXT NOT NULL DEFAULT '',
    app_id        TEXT NOT NULL,
    advisory_id   TEXT NOT NULL,
    priority      TEXT NOT NULL DEFAULT '',
    -- The version the finding was about, and for an update the version
    -- installed afterwards.
    from_version  TEXT NOT NULL DEFAULT '',
    to_version    TEXT NOT NULL DEFAULT '',
    fixed_in      TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX finding_events_at ON finding_events (at);
CREATE INDEX finding_events_finding ON finding_events (finding_id, at);

-- Existing findings start their history with what is known: when each was
-- first seen and, if resolved, when (the cause was not recorded).
INSERT INTO finding_events (finding_id, at, kind, host_id, host_name, workload_id, workload_name, image_ref,
    app_id, advisory_id, priority, from_version, fixed_in)
SELECT f.id, f.first_seen, 'opened', COALESCE(w.host_id, ''), COALESCE(h.name, ''), f.workload_id, COALESCE(w.name, ''),
    COALESCE(w.image_ref, ''), f.app_id, f.advisory_id, f.priority,
    COALESCE(json_extract(f.detail_json, '$.evidence.version'), ''), f.fixed_in
FROM findings f LEFT JOIN workloads w ON w.id = f.workload_id LEFT JOIN hosts h ON h.id = w.host_id;

INSERT INTO finding_events (finding_id, at, kind, host_id, host_name, workload_id, workload_name, image_ref,
    app_id, advisory_id, priority, from_version, fixed_in)
SELECT f.id, f.resolved_at, 'resolved', COALESCE(w.host_id, ''), COALESCE(h.name, ''), f.workload_id, COALESCE(w.name, ''),
    COALESCE(w.image_ref, ''), f.app_id, f.advisory_id, f.priority,
    COALESCE(json_extract(f.detail_json, '$.evidence.version'), ''), f.fixed_in
FROM findings f LEFT JOIN workloads w ON w.id = f.workload_id LEFT JOIN hosts h ON h.id = w.host_id
WHERE f.state = 'resolved' AND f.resolved_at IS NOT NULL;
