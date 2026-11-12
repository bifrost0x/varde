-- SPDX-License-Identifier: Apache-2.0
-- The limits a release read was made with (imagelayers.LimitsKey), so a
-- read that stopped at a limit is read again when the limits change. Empty
-- for a read whose limits are not known, which counts as other limits.
-- layer_reads.digest holds more than layer digests since the release
-- reader: the chain key of a layer record (imagelayers.LayerKeys) and the
-- digest of a cached image config.
ALTER TABLE release_reads ADD COLUMN limits TEXT NOT NULL DEFAULT '';
