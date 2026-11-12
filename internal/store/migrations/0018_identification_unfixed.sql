-- SPDX-License-Identifier: Apache-2.0
-- Open issues of a system package that no update fixes yet (ADR 0032):
-- shown on the system's page, not reported as findings.
ALTER TABLE identifications ADD COLUMN unfixed INTEGER NOT NULL DEFAULT 0;
