-- SPDX-License-Identifier: Apache-2.0
-- The version of the reader that wrote an image record. A record of an
-- older reader lacks what newer ones read (source packages, the rpm
-- database, Go modules) and is read again at once instead of after a week.
-- Records from before this migration count as format 0.
ALTER TABLE image_package_reads ADD COLUMN format INTEGER NOT NULL DEFAULT 0;
