-- SPDX-License-Identifier: Apache-2.0
-- Image repositories the user marked as "not an app": left out of the
-- coverage gaps and the public-route notices.

CREATE TABLE not_an_app (
    repository TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
