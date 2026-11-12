-- SPDX-License-Identifier: Apache-2.0
-- Every package installed on a host, as its package database lists it: the
-- full inventory, not only the packages of catalog apps.
CREATE TABLE host_packages (
    host_id  TEXT PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    distro   TEXT NOT NULL DEFAULT '',
    os       TEXT NOT NULL DEFAULT '',
    packages TEXT NOT NULL DEFAULT '[]',
    read_at  INTEGER NOT NULL
) STRICT;
