-- SPDX-License-Identifier: Apache-2.0
-- What the registry says about the image a container runs: what its tag
-- points to now, the newest tag on its track, and, when Varde read it, the
-- package list of that newer image (ADR 0045). One row per image as it runs
-- (repository, tag and digest) and platform.
CREATE TABLE upstream_checks (
    repository        TEXT NOT NULL,
    tag               TEXT NOT NULL,
    running_digest    TEXT NOT NULL,
    platform          TEXT NOT NULL DEFAULT '',
    head_digest       TEXT NOT NULL DEFAULT '',
    candidate_tag     TEXT NOT NULL DEFAULT '',
    candidate_digest  TEXT NOT NULL DEFAULT '',
    candidate         BLOB,
    candidate_read_at INTEGER NOT NULL DEFAULT 0,
    candidate_error   TEXT NOT NULL DEFAULT '',
    checked_at        INTEGER NOT NULL,
    error             TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (repository, tag, running_digest, platform)
) STRICT;

-- The upstream status of each container with image findings, as the last
-- analysis decided it (JSON of upstream.Status). Containers without a row
-- have no status; pages then say nothing about a newer image.
CREATE TABLE upstream_status (
    workload_id TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    computed_at INTEGER NOT NULL
) STRICT;

-- A finding snoozed until a fixed image appears: it opens again when the
-- upstream status names an image that fixes it, or when the snooze ends.
ALTER TABLE findings ADD COLUMN snooze_upstream INTEGER NOT NULL DEFAULT 0;
