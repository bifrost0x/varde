-- SPDX-License-Identifier: Apache-2.0
-- The sockets a host listens on, for its attack surface (ADR 0034).
ALTER TABLE host_packages ADD COLUMN listen TEXT NOT NULL DEFAULT '[]';
