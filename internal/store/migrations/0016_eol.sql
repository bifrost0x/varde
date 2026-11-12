-- SPDX-License-Identifier: Apache-2.0
-- Release lines and their end of life from endoflife.date, per product
-- (ADR 0029).
CREATE TABLE eol_releases (
    product    TEXT PRIMARY KEY,
    releases   TEXT NOT NULL DEFAULT '[]',
    fetched_at INTEGER NOT NULL
) STRICT;
