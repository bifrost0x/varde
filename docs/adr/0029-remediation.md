# 0029 Remediation: concrete updates, end of life, more channels, tour, resolved findings

Status: Accepted

## Context
A finding said "update to 1.121.0 or later". The user still had to find the tag that carries the
release in the form their image uses (`v1.121.0`, `1.27.4-alpine`, `4.0.15.2941-ls276`), find the
Compose file and know the commands. A version that is no longer supported got no attention until
an advisory named it. Homelab users often get notifications through Discord or Telegram. A new user
had no guided way through the pages (ADR 0020 asked for a product tour).

## Decision
- **The release tag that fixes it.** For a container with affected findings, Varde suggests the
  lowest release tag at or above the update target: the version that fixes all advisories of the
  running version together, or the best update on the running release line when the target leaves
  it. The tag keeps the form of the running one: the same prefix and image variant. Among
  linuxserver.io builds of one release, the newest build is suggested. Pre-releases are never a
  fix for a stable release.
- **Tag lists from the registry.** With registry versions on (ADR 0025), Varde reads the tag list of
  each repository whose containers have open affected findings, once a day, at most ten per run.
  It keeps only the app's release tags (table `repository_tags`, migration 0015). A suggestion
  from the list is verified. Without a list, the tag is built in the running form and marked as not
  seen in the registry; a distributor build number cannot be guessed and gives no suggestion.
- **Floating tags**: pull again and recreate, then check the version Varde reads.
- **Compose.** Containers created by Docker Compose carry their project, service, working directory
  and files as labels. The finding page names them, gives the `image:` line to change and the
  commands (`docker compose pull <service> && docker compose up -d <service>`). Varde suggests only;
  it never changes a host. The paths come from container labels and are shown as text.
- **End of life.** A catalog entry may name its product on endoflife.date (`eol`). With the setting
  `EOL_DATA` (off by default: it reveals the product names), Varde reads the release lines once a
  day per product (table `eol_releases`, migration 0016). The inventory marks a version whose
  line no longer gets fixes, with the newest supported release. An answer that does not name the
  product asked for is refused.
- **Discord and Telegram.** Two more channels, configured like the others through environment
  variables. Both carry their secret in the URL path (the webhook URL, the bot token), which the
  HTTP client does not redact; their errors redact it before they reach logs or the UI. Discord
  messages escape Markdown and disable mentions; Telegram messages are plain text.
- **Resolved findings in the weekly digest.** Findings Varde had notified about and that were
  resolved since the last weekly digest are listed there, once: the user learns that the update
  worked without a message of its own. Findings never notified are left out.
- **Proxy routes count for exposure.** Routes the Traefik API or Nginx Proxy Manager report make the
  container they forward to public (public domain) or LAN (internal domain), in the analysis and
  on the pages alike. A backend matches by host address and published port anywhere; by container
  network address or container/service name only on the host the proxy runs on, since those are
  unique only within one Docker host.
- **Product tour.** A seven-step walk through overview, network, inventory, findings, coverage and
  settings, started from the top bar and offered once on the first visit of the overview. It needs
  no inline script (CSP) and works with the keyboard (focus on the next action, Escape ends it). Its
  progress lives in sessionStorage and the "done" flag in localStorage; without storage the tour
  still works, it just does not resume or remember.

## Consequences
- In the lab, a Vaultwarden 1.30.0 Compose container gets `vaultwarden/server:1.37.4`, which fixes
  its 30 advisories together, with its compose files and commands.
- Integration management (enable, disable, sync, delete) was already on the network page.
- Not covered: suggestions for hosts and packages (the distribution's update tools apply);
  digest-pinned images; Compose files Varde cannot see (it reads labels, not files).
