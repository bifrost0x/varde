# 0035 Findings keep their identity and history; the UI groups them by what fixes them

Status: Accepted

## Context
Varde showed what is open, not what happened. A user who updated a container could not see that
the update fixed anything: `docker compose up -d` gives the container a new ID, the workload was
keyed by that ID, so every finding of the container was resolved and opened again. Fixed and
unchanged findings looked the same, acknowledgements and snoozes were lost, and urgent findings
notified a second time. Resolved findings were purged after 90 days with nothing left of them, and
nothing recorded why a finding ended.

The findings page listed one row per app or package version: a homelab with a few old images has
over a hundred rows, while the person in front of it has a handful of things to do (pull a newer
image here, install the updates there). The overview led with "219 new urgent findings".

## Decision
- **A recreated container is the same workload.** When a snapshot reports a container under a new
  ID and a stored container of the same name on that host is no longer reported (or was removed),
  the new one takes over its workload: the row keeps its ID and gets the new runtime ID. Docker
  keeps names unique on a host, so a new container under a known name is that container recreated.
  Workloads of other kinds already have stable runtime IDs.
- **History of every finding** (`finding_events`, migration 0027): opened, reopened, resolved,
  with host, workload, image, app, advisory, priority and versions copied into the row, so the
  history stays readable after workloads, hosts and resolved findings are purged. It has no
  foreign keys and is kept for two years. Existing findings start their history with their first
  seen and resolved times.
- **Why a finding ended.** The analysis passes the version of every app and package it checked;
  a finding that no longer matches is resolved as *updated* (another version, recorded with the
  new one), *uninstalled* (the app or package is gone from the workload), *removed* (the workload
  is gone) or *advisory* (same version, the advisory no longer names it). Only the first two count
  as fixed; the others are closed. User actions on findings stay in the audit log, which the
  history shows next to them.
- **History page and export.** "History" under Findings shows a period (7 to 365 days) per system
  or overall: fixed, new, open now, how findings ended, the median time to fix per priority, what
  has waited longest, and a timeline of one entry per analysis, workload and cause. The finding
  page shows its own history. A CSV export carries every event; cells that start like a formula
  are prefixed, since container and image names are chosen on the hosts. Printing the page is the
  report; there is no separate report format.
- **Findings grouped by what fixes them.** The default findings view has one card per container
  (pull a newer image and recreate it), per host's system packages (install the updates, with the
  distribution's command) or per app (update to the target version), ranked by priority and urgent
  count; the app and package groups behind each card fold out. Grouping by package and one row per
  advisory remain. The overview leads with the number of urgent updates to do and shows the top
  cards directly under the counters.

## Consequences
- An upgrade from an earlier version keeps the findings of recreated containers only from the next
  recreate on; containers recreated before the upgrade already have their own workloads.
- Two containers that swap names between two snapshots would swap histories. This needs a rename
  while both run, which `docker compose` does not do.
- The history grows with the number of finding changes, not with time: a homelab with a thousand
  image findings that are all replaced once a month adds about two thousand small rows a month.
