# 0026 Package databases and app manifests of images

Status: Accepted

## Context
A container's tag and labels are claims of the publisher. The image's package database says what is
actually installed: an app installed from its project's own repository (`jellyfin-server` from
repo.jellyfin.org in the linuxserver.io image) states its release there, also when the tag is
floating and the labels are missing, and it disagrees with the tag when someone upgraded the package
inside the container. Stage 3 also needs the distribution packages of images, with the native
version order of dpkg, rpm and apk, to match distribution security data.

The Docker API serves files of a container as a tar stream (`GET /containers/{id}/archive`). The
socket proxy Varde requires already allows it: it allows every GET under `/containers` and cannot
restrict the path.

## Decision
- **Read fixed files, nothing else.** Varde reads `/etc/os-release` (or `/usr/lib/os-release`,
  its target on Debian and Alpine), `/var/lib/dpkg/status` and `/lib/apk/db/installed`. The paths
  are a constant in the client. The one exception is the app manifest below, whose file name is
  fixed. Any other path is refused before a request. A symlink at one of the paths is not followed
  (a container could point it at another file), only a regular file of at most 16 MB is read, and
  the parsers keep only known fields with bounded lengths. dpkg packages count only when their
  status is installed.
- **The app's own manifest.** Many apps install through npm or pip, or copy their build, so no
  package database names them. Node apps ship their `package.json`, which names the app and its
  release. Varde reads `package.json` in the image's working directory (from the image
  configuration) and its parent (`/app/backend` runs code of `/app`), but not at `/`. The
  directory comes from the image, so the file name is fixed and the path must be absolute and clean.
  Only `name` and `version` are kept (1 MB limit). This rule is generic: a new release of a known
  app, or an app derived from its source label (ADR 0025), needs no catalog change.
- **Once per image, from an unchanged container.** An image ID names immutable content, so one read
  serves every container of the image on every host. The archive endpoint reads a container's live
  file system, though, so Varde first checks the change list of up to three containers of the
  image and reads from one whose package files and manifests are unchanged against the image; if
  none is, nothing is stored. One container cannot set the evidence of the others. Running
  containers are preferred. A read is
  repeated weekly, to see packages changed inside a container; a failed read after a day. At most
  eight images are read per sync, so a host with many new images is covered over a few syncs. A
  refusal (a proxy that blocks the endpoint) stops the round and does not fail the sync.
- **Stored per image, attached at analysis.** The table `image_packages` holds distro, OS name and
  the packages (at most 5000) per image ID. The analysis attaches them to the containers like the
  registry answer; the workload records stay unchanged. Rows of images not read for 30 days expire.
- **Evidence, not override.** An upstream package of the container's app (catalog `packages` with
  `versioning: upstream`) is one more observation: it gives the version when nothing else does,
  confirms a tag that agrees, and turns a disagreeing tag into a conflict, which cannot produce
  affected findings. Distribution packages give no version: backports keep the upstream number
  (ADR 0008). They are stored for stage 3.
- **A manifest counts only when it names the app**, by catalog ID, name, alias or the repository of
  its source. A base image's or a dependency's manifest says nothing about the app. A manifest
  version is evidence like an upstream package. On a development tag (`main`, `nightly`, `dev`,
  `edge`, …) the image runs code past the version its manifest names, and fixes may already be in.
  The version is then only reported: shown, but it cannot be affected.
- **On by default, with a setting.** It opens no new connection and needs no new privilege: the
  Docker access already allows it, and nothing leaves the server. Settings › Versions turns it off.
- Distribution versions are compared with the rules of dpkg (Debian Policy 5.6.12), rpm
  (rpmvercmp, including `~` and `^`) and apk-tools (`internal/version/distro.go`); the tests cover
  cases checked against the real tools.

## Consequences
- Images whose app comes from an upstream package get a version from what is installed, and tags
  that do not match the installed package are flagged.
- In the real corpus, Uptime Kuma `latest` (1.23.17) and Open WebUI `main` (0.13.3, reported) now
  have a version, from their `package.json`. Version coverage rose from 0.891 to 0.935. The
  linuxserver.io Jellyfin image confirms its build label with its upstream package.
- Python apps without a Node manifest (Frigate) and Go binaries are not covered yet. Python
  metadata lives in version-specific `site-packages` paths. Go build information sits inside the
  binary; reading it means scanning the entrypoint, which needs its own bounds.
- RPM databases (`rpmdb.sqlite`) and distroless package lists (`/var/lib/dpkg/status.d/`) are not
  read yet.
- Agents do not read packages yet; their snapshots carry none.
- Whoever controls the Varde server can read any file of any container through the same endpoint;
  this was already true and is a residual risk in the threat model.
