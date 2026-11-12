-- SPDX-License-Identifier: Apache-2.0
-- Evidence and trust of identifications (ADR 0023), and stable asset
-- identity across sources.

ALTER TABLE identifications ADD COLUMN trust TEXT NOT NULL DEFAULT '';
ALTER TABLE identifications ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE identifications ADD COLUMN purl TEXT NOT NULL DEFAULT '';

ALTER TABLE hosts ADD COLUMN macs_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE hosts ADD COLUMN machine_id TEXT NOT NULL DEFAULT '';

-- Assets are the machines Varde keeps apart over time. Their ID stays the
-- same while the evidence changes; keys tie evidence to an asset.
CREATE TABLE assets (
    id         TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
) STRICT;

-- Identity keys of an asset: strong keys (host record, Proxmox VMID,
-- machine-id, MAC) bind an asset; addresses are recorded but weak.
CREATE TABLE asset_keys (
    asset_id  TEXT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,
    value     TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (kind, value)
) STRICT;

CREATE INDEX asset_keys_asset ON asset_keys (asset_id);
