-- SPDX-License-Identifier: Apache-2.0
-- Who read an image's packages: empty for Varde itself (local Docker,
-- Docker over SSH), "agent:<host ID>" for an agent. An agent may not
-- overwrite what another source read (ADR 0033).
ALTER TABLE image_packages ADD COLUMN source TEXT NOT NULL DEFAULT '';
