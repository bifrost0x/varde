-- SPDX-License-Identifier: Apache-2.0
-- Operating system and package databases of images, read from a running
-- container of each image (ADR 0026).
CREATE TABLE image_packages (
    image_id TEXT PRIMARY KEY,
    distro   TEXT NOT NULL DEFAULT '',
    os       TEXT NOT NULL DEFAULT '',
    packages TEXT NOT NULL DEFAULT '[]',
    read_at  INTEGER NOT NULL,
    error    TEXT NOT NULL DEFAULT ''
) STRICT;
