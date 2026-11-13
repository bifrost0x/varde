-- SPDX-License-Identifier: Apache-2.0
-- The layer_reads keys a release read used (a JSON array: the image
-- config's digest and the chain keys of its layer records). After each
-- build the builder keeps only the layer reads the stored release reads
-- name, so the store it publishes does not grow with every layer it ever
-- read. Empty for a read from before, whose layer reads are dropped.
ALTER TABLE release_reads ADD COLUMN layers TEXT NOT NULL DEFAULT '';
