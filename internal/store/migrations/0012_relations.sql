-- SPDX-License-Identifier: Apache-2.0
-- The host record a host runs on (a Proxmox guest's node).
ALTER TABLE hosts ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
