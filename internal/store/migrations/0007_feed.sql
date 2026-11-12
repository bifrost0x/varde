-- SPDX-License-Identifier: Apache-2.0
-- State of the signed central feed: the last applied manifest. One row.

CREATE TABLE feed_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    sequence        INTEGER NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    verified_at     INTEGER NOT NULL,
    applied_at      INTEGER NOT NULL
) STRICT;
