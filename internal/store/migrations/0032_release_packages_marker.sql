-- SPDX-License-Identifier: Apache-2.0
-- What the release_packages table was filled from (the digest of the
-- package's releases blob), written in the same transaction as the rows:
-- an installation that starts with the package it already holds need not
-- write the table again.
CREATE TABLE release_packages_marker (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    marker TEXT NOT NULL
) STRICT;
