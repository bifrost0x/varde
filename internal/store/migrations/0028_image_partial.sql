-- SPDX-License-Identifier: Apache-2.0
-- An image read that stopped at a size or time bound: its packages are
-- checked, but a package missing from it is not counted as removed.
ALTER TABLE image_package_reads ADD COLUMN partial INTEGER NOT NULL DEFAULT 0;
