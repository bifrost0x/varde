# 0006 Docker access only through a GET-only socket proxy

Status: Accepted

## Context
Access to the Docker socket is equivalent to root on the host. Varde needs read access to
containers, images, events, info and version only.

## Decision
Varde talks to the Engine API exclusively through a socket proxy sidecar on an internal network,
configured to allow only the needed endpoints and to deny all non-GET methods. Varde refuses to start
with a directly mounted socket unless `VARDE_ALLOW_DIRECT_SOCKET=true`, and then warns persistently
in the UI. The Docker client issues GET requests only, enforced in the client itself. The verified
proxy image and its environment variables are documented in `docs/configuration.md`.

## Alternatives
- Direct read-only socket mount: `:ro` on a socket does not restrict API calls; rejected.
- Remote Docker API with TLS client certificates: possible later, more setup for users.

## Consequences
One extra container in the default deployment. Defence in depth: even a compromised Varde process
cannot create or exec containers through the proxy.
