-- SPDX-License-Identifier: Apache-2.0
-- Network scan runs, so the last result survives a restart and scheduled
-- scans can be told apart from manual ones. Only the newest runs are kept.
CREATE TABLE scan_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger          TEXT NOT NULL,
    networks         TEXT NOT NULL,
    started          INTEGER NOT NULL,
    ended            INTEGER NOT NULL,
    addresses        INTEGER NOT NULL,
    found            INTEGER NOT NULL,
    intercepted_json TEXT NOT NULL DEFAULT '[]',
    error            TEXT NOT NULL DEFAULT ''
) STRICT;
