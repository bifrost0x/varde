# Embedded trust root

`production.json` in this directory is the trust root every release build embeds: the public
keys an installation accepts for the data package and the uplink. It is placed here by the key
ceremony described in `docs/data-package.md` (`cmd/vardekeys`). Private keys never come near this repository.

Without the file a build has no embedded root: the data package is then not available and an
installation asks the public sources itself, unless `VARDE_FEED_ROOT_FILE` names a root.
