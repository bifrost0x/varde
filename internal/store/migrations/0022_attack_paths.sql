-- SPDX-License-Identifier: Apache-2.0
-- Attack paths through the infrastructure and how each finding relates to
-- them: on a path from the internet or the LAN, an amplifier, background
-- noise or unclear, with the reason (ADR 0034). The paths are recomputed on
-- every analysis run.
ALTER TABLE findings ADD COLUMN path_class TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN path_reason TEXT NOT NULL DEFAULT '';
CREATE TABLE attack_paths (
    id TEXT PRIMARY KEY,
    entry TEXT NOT NULL,
    score INTEGER NOT NULL,
    target TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    computed_at INTEGER NOT NULL
);
