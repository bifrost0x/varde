# 0027 Container drift

Status: Accepted

## Context
Varde learns a container's version from its image: labels, tags, the registry answer, the image's
package database and the app's manifest (ADR 0025, ADR 0026). A container can drift from that image
in two ways that matter for versions:

- The tag it was created from was pulled again and now points to a newer image, but the container
  was not recreated. The user believes they updated; the old release still runs.
- Packages were installed or upgraded inside the container, or the app's files were replaced. The
  image's package database and manifest then no longer describe the container.

## Decision
- **Pulled but not running.** For each container created from a tag, Varde asks the Docker API
  which local image the tag points to now (`GET /images/{name}/json`, once per reference and sync,
  references validated before the request). When it differs from the running image, the container
  carries `pulled_image_id`, and the inventory says to recreate it. Image events (pull, tag) start a
  sync, so this shows right after the pull.
- **Changed inside.** Varde reads the list of paths changed in the container's writable layer
  (`GET /containers/{id}/changes`), once a day per container, at most eight per sync, and at most
  4 MB per list. A container that writes many files into its own layer is skipped, not read in
  full. Varde keeps only the paths that carry version evidence: the package databases and the
  manifest paths of ADR 0026, as `changed_files`. Evidence from such a file is recorded without a
  version and not used: a version Varde cannot tie to this container is unknown.
- Both checks are read-only and need no new access. The change check runs only while reading
  package databases is enabled (`CONTAINER_PACKAGES`), whose evidence it qualifies.
- **Go build information was evaluated and not adopted.** Most of the corpus Go images report the
  main module version `(devel)`: Caddy, AdGuard Home, Portainer. Traefik, Syncthing, Authelia, Grafana
  and nginx-ui start through a shell script. Only Navidrome embeds its release. Release numbers are
  set with `-ldflags` and cannot be read generically. Scanning entrypoint binaries would cost a full
  read of each binary for almost no evidence.

## Consequences
- An update that was pulled but not applied is visible, with the step that applies it.
- Containers that install packages at start lose the package and manifest evidence of their image.
  This is deliberate: Varde does not know which state is running, so it does not claim one.
- The change state is kept in memory; after a restart it is read again over the next syncs.
