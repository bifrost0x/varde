-- SPDX-License-Identifier: Apache-2.0
-- One image record per source: Varde's own read (source '') and each
-- agent's (source 'agent:<host ID>'). A container uses Varde's read or the
-- one of its own host's agent, never another agent's, so one agent cannot
-- change what the containers of other hosts are checked against
-- (ADR 0033). The rows of image_packages are taken over; that table is no
-- longer written.
CREATE TABLE image_package_reads (
    image_id TEXT NOT NULL,
    source   TEXT NOT NULL DEFAULT '',
    distro   TEXT NOT NULL DEFAULT '',
    os       TEXT NOT NULL DEFAULT '',
    packages TEXT NOT NULL DEFAULT '[]',
    read_at  INTEGER NOT NULL,
    error    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (image_id, source)
) STRICT;
INSERT INTO image_package_reads (image_id, source, distro, os, packages, read_at, error)
    SELECT image_id, source, distro, os, packages, read_at, error FROM image_packages;
