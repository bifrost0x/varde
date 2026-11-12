# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0

# Base images are pinned by digest; Dependabot keeps them current.
ARG GO_IMAGE=golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG SOURCE_DATE_EPOCH=0
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# The image also ships the agent for linux/amd64 and linux/arm64, which the
# server installs on hosts and offers as updates (ADR 0031). On Linux the
# server's own binary is the agent of its platform.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -e; \
    build() { \
      CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -buildid= \
          -X github.com/bifrost0x/varde/internal/buildinfo.Version=${VERSION} \
          -X github.com/bifrost0x/varde/internal/buildinfo.Commit=${COMMIT} \
          -X github.com/bifrost0x/varde/internal/buildinfo.Date=${SOURCE_DATE_EPOCH}" \
        -o "$3" ./cmd/varde; \
    }; \
    agent=/out/root/usr/lib/varde/agent; \
    for arch in amd64 arm64; do build linux "$arch" "$agent/varde-linux-$arch"; done; \
    if [ "$TARGETOS" = linux ] && [ -f "$agent/varde-linux-$TARGETARCH" ]; then \
      ln -s "/usr/lib/varde/agent/varde-linux-$TARGETARCH" /out/root/varde; \
    else \
      build "$TARGETOS" "$TARGETARCH" /out/root/varde; \
    fi; \
    mkdir -p /out/data

FROM ${RUNTIME_IMAGE}
# distroless/static:nonroot provides CA certificates, tzdata and UID/GID 65532.
# A directory copy keeps the /varde symlink, so the server binary is in the
# image once.
COPY --from=build /out/root/ /
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/varde", "healthcheck"]
ENTRYPOINT ["/varde"]
CMD ["server"]
