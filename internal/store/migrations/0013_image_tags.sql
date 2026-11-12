-- SPDX-License-Identifier: Apache-2.0
-- Version tags the registries give the digests of running images, so a
-- floating tag ("latest") resolves to a release without guessing.
CREATE TABLE image_tags (
    repository TEXT NOT NULL,
    digest     TEXT NOT NULL,
    tag        TEXT NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL,
    error      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (repository, digest)
) STRICT;
