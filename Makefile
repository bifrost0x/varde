# SPDX-License-Identifier: Apache-2.0

# Image name is defined here once for local builds; CI defines its own in
# .github/workflows (IMAGE_NAME).
IMAGE          ?= bifrost0x/varde
VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT         ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
GOLANGCI_LINT  ?= golangci-lint
GOVULNCHECK_VERSION ?= v1.9.0

PKG     := github.com/bifrost0x/varde/internal/buildinfo
LDFLAGS := -s -w -buildid= \
	-X $(PKG).Version=$(VERSION) \
	-X $(PKG).Commit=$(COMMIT) \
	-X $(PKG).Date=$(SOURCE_DATE_EPOCH)

export CGO_ENABLED ?= 0

.PHONY: all build test test-short eval fuzz lint vuln license-check check run-dev image clean index index-fetch package

all: check build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/varde ./cmd/varde

test:
	CGO_ENABLED=1 go test -race -count=1 ./...

# Recognition measurement against the corpus (internal/eval); writes eval-report.md.
eval:
	EVAL_REPORT=$(CURDIR)/eval-report.md go test -count=1 -run TestCorpus ./internal/eval

test-short:
	go test -short ./...

# Short fuzz smoke over every Fuzz* target; override FUZZTIME for longer runs.
FUZZTIME ?= 10s
fuzz:
	@for pkg in $$(go list ./...); do \
		for f in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz' || true); do \
			echo "fuzz $$pkg $$f"; \
			go test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

lint:
	$(GOLANGCI_LINT) run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

license-check:
	./scripts/check-license-headers.sh

check: license-check lint test vuln

run-dev: build
	VARDE_LOG_FORMAT=text VARDE_LOG_LEVEL=debug VARDE_LISTEN_ADDR=127.0.0.1:8080 ./bin/varde server

image:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		-t $(IMAGE):$(VERSION) .

clean:
	go clean -testcache
	$(RM) -r bin dist coverage.out

# The first-party index (ADR 0038): index/images.tsv, embedded in the binary.
# index-fetch downloads the public app store lists that serve as pointers;
# index visits the projects and writes the table. Fetched pages are kept in
# .cache, so a rerun asks nothing twice.
INDEX_TOPICS ?= self-hosted,selfhosted,homelab

index-fetch:
	mkdir -p .cache/index-lists
	curl -fsSL -o .cache/index-lists/unraid.json https://raw.githubusercontent.com/Squidly271/AppFeed/master/applicationFeed.json
	curl -fsSL -o .cache/index-lists/umbrel.tar.gz https://codeload.github.com/getumbrel/umbrel-apps/tar.gz/refs/heads/master

index:
	go run ./cmd/indexbuilder -lists .cache/index-lists -topics $(INDEX_TOPICS) -topic-pages 3 -cache .cache/index -out index/images.tsv

# Builds the data package by hand (docs/data-package.md). Needs the private
# feed key in VARDE_FEED_KEY and a trust root that lists it (-root, or the
# one built in). The daily workflow does this; nothing is published here.
package:
	rm -rf .cache/package/feed
	go run ./cmd/packagebuilder -db .cache/package/builder.db -out .cache/package/feed $(PACKAGE_FLAGS)
