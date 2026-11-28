-- SPDX-License-Identifier: Apache-2.0
-- What Varde read of the packages inside a container's image and compares
-- with security data (JSON of identify.PackageCheck, empty when nothing was
-- read), so the pages can say whether an app they do not recognise was
-- still checked (ADR 0047).
ALTER TABLE identifications ADD COLUMN packages_json TEXT NOT NULL DEFAULT '';
