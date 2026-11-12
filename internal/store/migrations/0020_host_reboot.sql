-- SPDX-License-Identifier: Apache-2.0
-- The running kernel of a host and why it needs a restart for its updates
-- to take effect; empty when it does not or Varde cannot tell.
ALTER TABLE host_packages ADD COLUMN kernel TEXT NOT NULL DEFAULT '';
ALTER TABLE host_packages ADD COLUMN reboot TEXT NOT NULL DEFAULT '';
