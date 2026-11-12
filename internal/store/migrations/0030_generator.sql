-- SPDX-License-Identifier: Apache-2.0
-- State of the daily data build (catalog generator and release reads) and
-- the release package lists an installation receives in the signed package.
-- The builder tables exist in every store but only the builder fills them.

-- One row per candidate image. checked_at and shipped_at are NULL until the
-- candidate was checked or shipped.
CREATE TABLE gen_candidates (
    image        TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    weight       INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT '',
    failed_check TEXT NOT NULL DEFAULT '',
    entry_yaml   TEXT NOT NULL DEFAULT '',
    inputs_hash  TEXT NOT NULL DEFAULT '',
    checked_at   INTEGER,
    shipped_at   INTEGER
) STRICT;

-- Candidates() reads the unchecked rows by weight and the checked ones by
-- age; one index on checked_at serves both ranges.
CREATE INDEX gen_candidates_checked ON gen_candidates (checked_at);

-- What was read from an image layer, by digest: a layer is immutable, so the
-- cache never goes stale. files is gzip-compressed JSON of the kept files.
-- Looked up by primary key only, so there is no further index: the table
-- is published with the store and every index would grow it.
CREATE TABLE layer_reads (
    digest  TEXT PRIMARY KEY,
    files   BLOB NOT NULL,
    partial INTEGER NOT NULL DEFAULT 0,
    read_at INTEGER NOT NULL
) STRICT;

-- The latest release read per app, image and platform. line is the JSON
-- the caller wrote; the store keeps it opaque.
CREATE TABLE release_reads (
    app_id       TEXT NOT NULL,
    image        TEXT NOT NULL,
    platform     TEXT NOT NULL,
    tag          TEXT NOT NULL,
    index_digest TEXT NOT NULL,
    line         BLOB NOT NULL,
    read_at      INTEGER NOT NULL,
    PRIMARY KEY (app_id, image, platform)
) STRICT;

-- The release package lists of an installation, replaced as a whole with
-- each package. The key prefix (app_id, image) serves ReleasePackagesFor.
CREATE TABLE release_packages (
    app_id   TEXT NOT NULL,
    image    TEXT NOT NULL,
    platform TEXT NOT NULL,
    tag      TEXT NOT NULL,
    version  TEXT NOT NULL,
    line     BLOB NOT NULL,
    PRIMARY KEY (app_id, image, platform)
) STRICT;
