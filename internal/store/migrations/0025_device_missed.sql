-- SPDX-License-Identifier: Apache-2.0
-- How many scans in a row a known device did not answer. Packets get lost
-- (WLAN, NAT, routers that throttle scans): a device is kept, marked, after
-- one missed scan and removed after the second.
ALTER TABLE devices ADD COLUMN missed INTEGER NOT NULL DEFAULT 0;
