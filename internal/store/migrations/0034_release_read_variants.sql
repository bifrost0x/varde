-- SPDX-License-Identifier: Apache-2.0
-- Release reads are keyed by the platform of their line with its variant
-- ("linux/arm64/v8"), as installations keep them, so two images of one
-- architecture in different variants are two reads instead of one
-- replacing the other. Reads from before were keyed "os/architecture";
-- those whose line names a variant move to the key with it. No such key
-- existed before, so none collides.
UPDATE release_reads
SET platform = platform || '/' || json_extract(CAST(line AS TEXT), '$.platform.variant')
WHERE json_valid(CAST(line AS TEXT))
  AND json_type(CAST(line AS TEXT), '$.platform.variant') = 'text'
  AND json_extract(CAST(line AS TEXT), '$.platform.variant') != ''
  AND platform = json_extract(CAST(line AS TEXT), '$.platform.os') || '/' || json_extract(CAST(line AS TEXT), '$.platform.architecture');
