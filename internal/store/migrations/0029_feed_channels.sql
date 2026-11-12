-- SPDX-License-Identifier: Apache-2.0
-- The data package and the uplink are two channels of one feed client.
-- Each keeps its own rollback floor, so returning from the uplink (newer
-- sequence) to the package (older sequence) is not refused, while a replay
-- inside one channel still is.
ALTER TABLE feed_state ADD COLUMN channel TEXT NOT NULL DEFAULT 'feed';

CREATE TABLE feed_floor (
    channel         TEXT PRIMARY KEY,
    sequence        INTEGER NOT NULL,
    manifest_sha256 TEXT NOT NULL
) STRICT;

-- A feed applied before this migration came from the static feed mode or
-- from the uplink switch; its sequence stays the floor of both.
INSERT INTO feed_floor (channel, sequence, manifest_sha256)
    SELECT 'feed', sequence, manifest_sha256 FROM feed_state WHERE id = 1;
INSERT INTO feed_floor (channel, sequence, manifest_sha256)
    SELECT 'uplink', sequence, manifest_sha256 FROM feed_state WHERE id = 1;
