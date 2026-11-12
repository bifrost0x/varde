-- SPDX-License-Identifier: Apache-2.0
-- Release tags of the repositories whose containers have affected findings,
-- so Varde can name the tag that fixes them (ADR 0029).
CREATE TABLE repository_tags (
    repository TEXT PRIMARY KEY,
    tags       TEXT NOT NULL DEFAULT '[]',
    checked_at INTEGER NOT NULL,
    error      TEXT NOT NULL DEFAULT ''
) STRICT;
